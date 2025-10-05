# app.py - Main Flask application with real Azure authentication and fixed IP calculations
from flask import Flask, render_template, session, redirect, url_for, request
import os
import json
import msal
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Azure AD Configuration
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
TENANT_ID = os.environ.get('TENANT_ID')
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/User.Read"]
REDIRECT_PATH = "/auth/callback"

# Create MSAL app instance
msal_app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET
)

@app.route('/')
def home():
    """Home page - shows login or dashboard"""
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    else:
        return render_template('login.html')

@app.route('/login')
def login():
    """Handle Azure AD login - real OAuth flow"""
    # Generate authentication URL with explicit redirect URI
    auth_url = msal_app.get_authorization_request_url(
        SCOPE,
        redirect_uri="http://localhost:5000/auth/callback"
    )
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    """Handle the callback from Azure AD"""
    if 'code' in request.args:
        # Exchange authorization code for tokens
        result = msal_app.acquire_token_by_authorization_code(
            request.args['code'],
            scopes=SCOPE,
            redirect_uri="http://localhost:5000/auth/callback"
        )
        
        if 'access_token' in result:
            session['access_token'] = result['access_token']
            
            # Get user info from Microsoft Graph
            try:
                headers = {'Authorization': f"Bearer {result['access_token']}"}
                user_response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
                
                if user_response.status_code == 200:
                    user_data = user_response.json()
                    session['user'] = {
                        'name': user_data.get('displayName', 'Unknown User'),
                        'email': user_data.get('mail', user_data.get('userPrincipalName', 'No email'))
                    }
                    return redirect(url_for('home'))
                else:
                    return f"Graph API failed: {user_response.status_code}", 400
                    
            except Exception as e:
                return f"Exception during user info retrieval: {str(e)}", 400
        else:
            return f"Token exchange failed: {result.get('error', 'Unknown error')}", 400
    
    return "Authentication cancelled - no authorization code received.", 400

@app.route('/logout')
def logout():
    """Clear session and log out"""
    session.clear()
    return redirect(url_for('home'))

def get_azure_token():
    """Helper to get Azure Resource Manager token"""
    accounts = msal_app.get_accounts()
    if not accounts:
        return None
    
    result = msal_app.acquire_token_silent(
        ["https://management.azure.com/user_impersonation"],
        account=accounts[0]
    )
    
    if result and 'access_token' in result:
        return result['access_token']
    
    return None

@app.route('/api/subscriptions')
def api_subscriptions():
    """API endpoint to list real Azure subscriptions"""
    if 'user' not in session:
        return json.dumps({'error': 'Not authenticated'}), 401
    
    try:
        azure_token = get_azure_token()
        if not azure_token:
            return json.dumps({'error': 'Failed to acquire Azure Resource Manager token', 'redirect': '/login'}), 401
        
        headers = {
            'Authorization': f"Bearer {azure_token}",
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            'https://management.azure.com/subscriptions?api-version=2020-01-01',
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            subscriptions = []
            
            for sub in data.get('value', []):
                subscriptions.append({
                    'id': sub['subscriptionId'],
                    'name': sub['displayName'],
                    'state': sub['state']
                })
            
            return json.dumps(subscriptions, indent=2)
        else:
            return json.dumps({'error': f'Azure API error: {response.status_code}'}), 500
            
    except Exception as e:
        return json.dumps({'error': f'Request failed: {str(e)}'}), 500

@app.route('/api/networks/<subscription_id>')
def api_networks(subscription_id):
    """API endpoint to list real VNets with accurate IP utilization data"""
    if 'user' not in session:
        return json.dumps({'error': 'Not authenticated'}), 401
    
    try:
        azure_token = get_azure_token()
        if not azure_token:
            return json.dumps({'error': 'Failed to acquire Azure Resource Manager token', 'redirect': '/login'}), 401
        
        headers = {
            'Authorization': f"Bearer {azure_token}",
            'Content-Type': 'application/json'
        }
        
        # Call Azure Network API to get virtual networks
        response = requests.get(
            f'https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks?api-version=2021-02-01',
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            networks = []
            
            for vnet in data.get('value', []):
                network = {
                    'id': vnet['id'],
                    'name': vnet['name'],
                    'location': vnet['location'],
                    'resourceGroup': vnet['id'].split('/')[4] if '/' in vnet['id'] else 'N/A',
                    'addressSpace': vnet['properties'].get('addressSpace', {}).get('addressPrefixes', []),
                    'subnets': []
                }
                
                # Process subnet information with accurate IP utilization
                for subnet in vnet['properties'].get('subnets', []):
                    subnet_prefix = subnet['properties'].get('addressPrefix', 'N/A')
                    
                    # Calculate subnet capacity from CIDR notation
                    total_ips = calculate_subnet_capacity(subnet_prefix)
                    reserved_ips = 5 if total_ips > 0 else 0  # Azure reserves 5 IPs per subnet
                    usable_ips = max(0, total_ips - reserved_ips)
                    
                    # Get actual IP usage from ipConfigurations (this is accurate!)
                    ip_configs = subnet['properties'].get('ipConfigurations', [])
                    used_ips = len(ip_configs)
                    available_ips = max(0, usable_ips - used_ips)
                    utilization_percent = (used_ips / usable_ips * 100) if usable_ips > 0 else 0
                    
                    # Extract IP consumer resource names
                    consumers = []
                    for ip_config in ip_configs:
                        resource_id = ip_config.get('id', 'Unknown Resource')
                        # Extract resource name from full Azure resource ID
                        if '/' in resource_id:
                            parts = resource_id.split('/')
                            if len(parts) >= 9:
                                resource_name = parts[8]  # Typically the NIC or resource name
                                consumers.append(resource_name)
                            else:
                                consumers.append(parts[-1])
                        else:
                            consumers.append(resource_id)
                    
                    subnet_info = {
                        'name': subnet['name'],
                        'addressPrefix': subnet_prefix,
                        'totalIPs': total_ips,
                        'usableIPs': usable_ips,
                        'availableIPs': available_ips,
                        'usedIPs': used_ips,
                        'utilizationPercent': round(utilization_percent, 1),
                        'utilizationStatus': get_utilization_status(utilization_percent),
                        'consumers': consumers[:5]  # Limit to first 5 consumers for display
                    }
                    
                    network['subnets'].append(subnet_info)
                
                networks.append(network)
            
            # Get private endpoints for this subscription
            pe_response = requests.get(
                f'https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/privateEndpoints?api-version=2021-02-01',
                headers=headers
            )
            
            private_endpoints = []
            if pe_response.status_code == 200:
                pe_data = pe_response.json()
                for pe in pe_data.get('value', []):
                    private_endpoints.append({
                        'name': pe['name'],
                        'location': pe['location'],
                        'resourceGroup': pe['id'].split('/')[4] if '/' in pe['id'] else 'N/A',
                        'subnet': pe['properties'].get('subnet', {}).get('id', '').split('/')[-1] if pe['properties'].get('subnet') else 'Unknown',
                        'privateLinkServiceConnections': len(pe['properties'].get('privateLinkServiceConnections', []))
                    })
            
            # Calculate summary statistics
            total_subnets = sum(len(net['subnets']) for net in networks)
            total_used_ips = sum(sum(subnet['usedIPs'] for subnet in net['subnets']) for net in networks)
            total_available_ips = sum(sum(subnet['availableIPs'] for subnet in net['subnets']) for net in networks)
            
            return json.dumps({
                'networks': networks,
                'privateEndpoints': private_endpoints,
                'summary': {
                    'totalNetworks': len(networks),
                    'totalPrivateEndpoints': len(private_endpoints),
                    'totalSubnets': total_subnets,
                    'totalUsedIPs': total_used_ips,
                    'totalAvailableIPs': total_available_ips
                }
            }, indent=2)
        else:
            return json.dumps({'error': f'Azure VNet API error: {response.status_code}'}), 500
            
    except Exception as e:
        return json.dumps({'error': f'Request failed: {str(e)}'}), 500

def calculate_subnet_capacity(cidr):
    """Calculate total IP addresses in a CIDR block"""
    try:
        if '/' not in cidr or cidr == 'N/A':
            return 0
        network, prefix_len = cidr.split('/')
        prefix_len = int(prefix_len)
        return 2 ** (32 - prefix_len)
    except:
        return 0

def get_utilization_status(percent):
    """Return utilization status based on percentage"""
    if percent >= 90:
        return 'critical'  # Red - Very high usage
    elif percent >= 75:
        return 'warning'   # Yellow - High usage
    elif percent >= 50:
        return 'moderate'  # Orange - Moderate usage
    else:
        return 'healthy'   # Green - Low usage

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
# CodeBeamer Admin Session Validation System

## Overview

This system implements a secure authentication flow where the admin user (`sejin.park`) must be logged in first before allowing the `vectorCAST` user to be auto-logged in. This ensures proper access control and session management.

## How It Works

1. **Admin Session Required**: The admin user (`sejin.park`) must be logged in to CodeBeamer first
2. **Admin Token Validation**: The system validates the admin's JWT token
3. **Conditional Access**: Only if the admin session is valid, the `vectorCAST` user can be auto-logged in
4. **Secure Proxy**: All proxy requests require admin token validation

## API Endpoints

### 1. Test Admin Session
```
GET /admin-session-test?token=ADMIN_JWT_TOKEN
```
- Validates if the provided admin token is valid and belongs to `sejin.park`
- Returns detailed information about the admin session

### 2. Get vectorCAST Token (requires admin validation)
```
GET /api/auth/jwt?adminToken=ADMIN_JWT_TOKEN
```
- Requires a valid admin token
- Returns a JWT token for `vectorCAST` user if admin session is valid
- Returns 401 if no admin token provided
- Returns 403 if admin session is invalid

### 3. Validate Admin Token
```
GET /api/auth/validate-admin?token=ADMIN_JWT_TOKEN
```
- Validates admin token and returns user information
- Useful for checking admin session status

### 4. Proxy Access (requires admin validation)
```
GET /codebeamer-proxy/*?adminToken=ADMIN_JWT_TOKEN
```
- All proxy requests require admin token validation
- Automatically adds vectorCAST JWT token to requests
- Returns 401/403 if admin validation fails

## Usage Examples

### Testing Admin Session
```bash
curl "http://localhost:3001/admin-session-test?token=eyJ0eXAiOiJKV1QiLCJpZ25vcmVBcGlBY2Nlc3NQZXJtaXNzaW9uIjp0cnVlLCJpZ25vcmVUaHJvdHRsaW5nIjp0cnVlLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjb2RlQmVhbWVyIiwibmFtZSI6InNlamluLnBhcmsiLCJleHAiOjE3NzA3MjY1ODQsInR5cGUiOiJhY2Nlc3MiLCJpYXQiOjE3NTQ5NTg1ODR9.5k-QHKfHBgCa6L5dKlzE-WAQYukTEvDoxMZOlcuVWq0"
```

### Getting vectorCAST Token
```bash
curl "http://localhost:3001/api/auth/jwt?adminToken=YOUR_ADMIN_TOKEN"
```

### Using Proxy with Admin Validation
```bash
curl "http://localhost:3001/codebeamer-proxy/login.spr?adminToken=YOUR_ADMIN_TOKEN"
```

## Web Interface

Visit `http://localhost:3001/admin-test.html` to use the interactive testing interface.

## Security Features

1. **Admin Session Validation**: All vectorCAST access requires valid admin session
2. **Token Expiration**: JWT tokens have expiration times
3. **Role-based Access**: Different roles for admin and user accounts
4. **Secure Headers**: Proper authorization headers for all requests

## Configuration

### User Credentials
```javascript
const userCredentials = { 
    'vectorCAST': { username: 'vectorCAST', password: '1234', role: 'user' },
    'mds': { username: 'mds', password: '1234', role: 'user' },
    'sejin.park': { username: 'sejin.park', password: '1234', role: 'admin' }
};
```

### JWT Configuration
```javascript
const CB_JWT_SECRET = "CB-ENCRYPTED-...";
const CB_TOKEN_VALID_MINUTES = 262800; // 6 months
const CB_TOKEN_RENEW_TIMEFRAME = 30; // 30 minutes
```

## Error Handling

- **401 Unauthorized**: Admin token not provided
- **403 Forbidden**: Admin session invalid or expired
- **500 Internal Server Error**: Server-side errors

## Testing

1. Start the server: `node app.js`
2. Open `http://localhost:3001/admin-test.html`
3. Enter the admin JWT token
4. Test the admin session validation
5. Get vectorCAST token if admin is valid
6. Test proxy access

## Troubleshooting

### Admin Session Invalid
- Ensure `sejin.park` is logged in to CodeBeamer
- Check if the JWT token is expired
- Verify the token belongs to `sejin.park`

### Proxy Access Denied
- Make sure admin token is provided in query parameter or header
- Check if admin session is still valid
- Verify the token format is correct

### Token Expired
- Admin needs to log in again to CodeBeamer
- Get a new JWT token for admin session
- Update the token in your application

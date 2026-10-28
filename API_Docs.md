# Vendiant API Sample Payloads

For breach platform webhook callbacks, see [Webhook_Docs.md](./Webhook_Docs.md).

## API Configuration
- **Base URL**: `https://vendiant-api.example.com`
- **Authentication**: X-API-Key header required for all endpoints
- **Content-Type**: `application/json` for POST requests

## Headers for All Requests
```json
{
  "X-API-Key": "vnd_exampleexampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU",
  "Content-Type": "application/json",
  "Accept": "application/json"
}
```

---

## 1. Health Check Endpoint

### `GET /vendiant/health`
**Description**: Check API health status
**Authentication**: None required

**cURL Example**:
```bash
curl -X GET "https://vendiant-api.example.com/vendiant/health"
```

**Expected Response**:
```json
{
  "status": "healthy",
  "service": "vendiant-api",
  "timestamp": "2025-09-25T05:30:00.123456"
}
```

---

## 2. Debug Domains Endpoint

### `GET /vendiant/debug/domains`
**Description**: List all available domains (for debugging)
**Authentication**: Any valid API key

**cURL Example**:
```bash
curl -X GET \
  -H "X-API-Key: vnd_exampleexampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/debug/domains"
```

**Expected Response**:
```json
{
  "total_vendors": 25,
  "vendors_with_domains": 23,
  "domains": [
    {"domain": "example.com", "name": "Example Corp"},
    {"domain": "test-company.org", "name": "Test Company"},
    {"domain": "secure-vendor.net", "name": "Secure Vendor Inc"}
  ],
  "raw_vendor_sample": [
    {
      "id": 1,
      "name": "Example Corp",
      "domain": "example.com",
      "securityScore": 750
    }
  ]
}
```

---

## 3. Get All Vendors

### `GET /vendiant/vendors`
**Description**: Retrieve list of all vendors
**Authentication**: Read access required

**cURL Example**:
```bash
curl -X GET \
  -H "X-API-Key: vnd_exampleexampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/vendors"
```

**Expected Response**:
```json
[
  {
    "id": 1,
    "domain": "example.com"
  },
  {
    "id": 2,
    "domain": "test-company.org"
  },
  {
    "id": 3,
    "domain": "secure-vendor.net"
  }
]
```

---

## 4. Get Domain Security Score

### `GET /vendiant/domain/{domain}/score`
**Description**: Get overall security risk score for a domain
**Authentication**: Read access required

**cURL Examples**:

**Valid Domain**:
```bash
curl -X GET \
  -H "X-API-Key: vnd_exampleexampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/domain/example.com/score"
```

**Expected Response (Success)**:
```json
{
  "domain": "example.com",
  "overall_risk_score": 750.5,
  "risk_level": "Medium",
  "vendor_name": "Example Corporation",
  "last_updated": "2025-09-20T10:30:00Z"
}
```

**Expected Response (Domain Not Found)**:
```json
{
  "detail": "No vendor found for domain: nonexistent.com"
}
```

**Expected Response (Invalid Domain)**:
```bash
curl -X GET \
  -H "X-API-Key: vnd_exampleexampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/domain/'; DROP TABLE vendors; --/score"
```
```json
{
  "detail": "Domain contains invalid characters"
}
```

---

## 5. Get Domain Security Report

### `GET /vendiant/domain/{domain}/report`
**Description**: Get comprehensive security report for a domain
**Authentication**: Read access required

**cURL Example**:
```bash
curl -X GET \
  -H "X-API-Key: vnd_exampleexampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/domain/example.com/report"
```

**Expected Response**:
```json
{
  "domain": "example.com",
  "overall_risk_score": 750.5,
  "risk_level": "Medium",
  "vendor_info": {
    "id": 1,
    "name": "Example Corporation",
    "domain": "example.com",
    "grade": "B+",
    "tier": "Tier 1",
    "industry": "Technology"
  },
  "vulnerabilities": {
    "total_found": 15,
    "critical": 0,
    "high": 2,
    "medium": 8,
    "low": 5,
    "details": [
      {
        "title": "SSL Certificate Expiring Soon",
        "severity": "medium",
        "description": "SSL certificate expires in 30 days"
      }
    ]
  },
  "network": {
    "open_ports": [80, 443, 22],
    "ssl_grade": "A-",
    "dns_security": "Good"
  },
  "encryption": {
    "ssl_enabled": true,
    "tls_version": "1.3",
    "cipher_strength": "Strong"
  },
  "reputation": {
    "blacklist_status": "Clean",
    "threat_intelligence": "No threats detected"
  },
  "scan_summary": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 8,
    "LOW": 5,
    "INFO": 10
  },
  "generated_at": "2025-09-25T05:30:00.123456"
}
```

---

## 6. Add New Vendor

### `POST /vendiant/vendor`
**Description**: Create a new vendor in the system
**Authentication**: Admin access required

**Request Body Schema**:
```json
{
  "name": "string (required, 1-255 chars)",
  "domain": "string (required, 3-253 chars, valid domain format)",
  "portfolio": "string (optional, max 100 chars)",
  "tier": "string (optional, max 50 chars)"
}
```

**cURL Example (Success)**:
```bash
curl -X POST \
  -H "X-API-Key: vnd_exampleexampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Security Company",
    "domain": "newsecurity.com",
    "portfolio": "Cybersecurity",
    "tier": "Tier 2"
  }' \
  "https://vendiant-api.example.com/vendiant/vendor"
```

**Expected Response (Success)**:
```json
{
  "status": "success",
  "message": "Vendor 'New Security Company' with domain 'newsecurity.com' added successfully",
  "data": {
    "id": 26,
    "name": "New Security Company",
    "domain": "newsecurity.com",
    "tier": "Tier 2",
    "portfolio": "Cybersecurity",
    "created_at": "2025-09-25T05:30:00.123456",
    "updated_at": "2025-09-25T05:30:00.123456"
  }
}
```

**cURL Example (Invalid Data)**:
```bash
curl -X POST \
  -H "X-API-Key: vnd_exampleexampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "",
    "domain": "invalid-domain",
    "portfolio": "Tech"
  }' \
  "https://vendiant-api.example.com/vendiant/vendor"
```

**Expected Response (Validation Error)**:
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "name"],
      "msg": "Vendor name cannot be empty"
    },
    {
      "type": "value_error", 
      "loc": ["body", "domain"],
      "msg": "Invalid domain format"
    }
  ]
}
```

**cURL Example (Malicious Input)**:
```bash
curl -X POST \
  -H "X-API-Key: vnd_exampleexampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<script>alert(\"XSS\")</script>",
    "domain": "example.com; DROP TABLE vendors; --",
    "portfolio": "Technology"
  }' \
  "https://vendiant-api.example.com/vendiant/vendor"
```

**Expected Response (Security Block)**:
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "name"],
      "msg": "Vendor name contains invalid characters"
    },
    {
      "type": "value_error",
      "loc": ["body", "domain"], 
      "msg": "Domain contains invalid characters"
    }
  ]
}
```

---

## 7. Delete Vendor by Domain

### `DELETE /vendiant/domain/{domain}`
**Description**: Delete a vendor and all associated data by domain
**Authentication**: Admin access required

**cURL Example (Success)**:
```bash
curl -X DELETE \
  -H "X-API-Key: vnd_exampleexampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/domain/newsecurity.com"
```

**Expected Response (Success)**:
```json
{
  "status": "success",
  "message": "Vendor 'New Security Company' with domain 'newsecurity.com' deleted successfully",
  "data": {
    "id": 26,
    "name": "New Security Company",
    "domain": "newsecurity.com"
  }
}
```

**Expected Response (Not Found)**:
```bash
curl -X DELETE \
  -H "X-API-Key: vnd_exampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/domain/nonexistent.com"
```
```json
{
  "detail": "No vendor found for domain: nonexistent.com"
}
```

**Expected Response (Invalid Domain)**:
```bash
curl -X DELETE \
  -H "X-API-Key: vnd_exampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU" \
  "https://vendiant-api.example.com/vendiant/domain/'; DROP TABLE vendors; --"
```
```json
{
  "detail": "Domain contains invalid characters"
}
```

---

## Error Responses

### Authentication Errors

**Missing API Key**:
```json
{
  "detail": "API key is required"
}
```

**Invalid API Key**:
```json
{
  "detail": "Invalid API key"
}
```

**Insufficient Permissions**:
```json
{
  "detail": "Insufficient permissions for this operation"
}
```

### Rate Limiting

**Rate Limit Exceeded**:
```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

### Server Errors

**Internal Server Error**:
```json
{
  "detail": "Internal server error while processing request"
}
```

---

## Rate Limit Headers

All successful responses include rate limiting information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1695622800
X-RateLimit-Scope: per-hour
```

---

## Security Headers

All responses include security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

---

## Testing with Different API Keys

### Read-Only Access Key
```bash
X-API-Key: vnd_exampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU
```
- Can access: GET endpoints (vendors, scores, reports)
- Cannot access: POST, DELETE endpoints

### Admin Access Key
```bash
X-API-Key: vnd_exampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU
```
- Can access: All endpoints
- Can manage: Vendors, API keys, system configuration

---

## Postman Collection

You can import these examples into Postman by creating a new collection with the following structure:

1. **Environment Variables**:
   - `baseUrl`: `https://vendiant-api.example.com`
   - `readApiKey`: `vnd_exampley_kH1exn_PPQaGq1eVsmbgRteIST-zTU`
   - `adminApiKey`: `vnd_exampleadmin_kH1exn_PPQaGq1eVsmbgRteIST-zTU`

2. **Collection Headers**:
   - `X-API-Key`: `{{readApiKey}}` or `{{adminApiKey}}`
   - `Content-Type`: `application/json`

3. **Test Scripts** (add to each request):
```javascript
pm.test("Status code is 200 or 201", function () {
    pm.expect(pm.response.code).to.be.oneOf([200, 201]);
});

pm.test("Response has required security headers", function () {
    pm.expect(pm.response.headers.get("X-Content-Type-Options")).to.equal("nosniff");
    pm.expect(pm.response.headers.get("X-Frame-Options")).to.equal("DENY");
});
```

This comprehensive guide covers all endpoints with realistic examples and expected responses for both success and error scenarios.

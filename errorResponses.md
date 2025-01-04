### 1. Invalid Challenge Response
```json
https://acme-staging-v02.api.letsencrypt.org/acme/authz/177930184/15531485764
{
  "identifier": {
    "type": "dns",
    "value": "sudip.com"
  },
  "status": "invalid",
  "expires": "2025-01-05T03:59:01Z",
  "challenges": [
    {
      "type": "http-01",
      "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/177930184/15531485764/zwW3Tw",
      "status": "invalid",
      "validated": "2024-12-29T03:59:05Z",
      "error": {
        "type": "urn:ietf:params:acme:error:unauthorized",
        "detail": "66.96.149.18: Invalid response from http://sudip.com/.well-known/acme-challenge/EteD_DgwLkY15Iwzn_4fgZHeobTP6teHif7WWcyq1UM: \"\u003c!DOCTYPE html PUBLIC \\\"-//W3C//DTD XHTML 1.0 Transitional//EN\\\"\\n    \\\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\\\"\u003e\\n\\n\u003c\"",
        "status": 403
      },
      "token": "EteD_DgwLkY15Iwzn_4fgZHeobTP6teHif7WWcyq1UM",
      "validationRecord": [
        {
          "url": "http://sudip.com/.well-known/acme-challenge/EteD_DgwLkY15Iwzn_4fgZHeobTP6teHif7WWcyq1UM",
          "hostname": "sudip.com",
          "port": "80",
          "addressesResolved": [
            "66.96.149.18"
          ],
          "addressUsed": "66.96.149.18"
        }
      ]
    }
  ]
}
```

### 2. NXDomain
```json

https://acme-staging-v02.api.letsencrypt.org/acme/authz/177930184/15532244504
{
  "identifier": {
    "type": "dns",
    "value": "susfasfasfasfdip.com"
  },
  "status": "invalid",
  "expires": "2025-01-05T06:08:46Z",
  "challenges": [
    {
      "type": "http-01",
      "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/177930184/15532244504/bGMLyQ",
      "status": "invalid",
      "validated": "2024-12-29T06:08:51Z",
      "error": {
        "type": "urn:ietf:params:acme:error:dns",
        "detail": "DNS problem: NXDOMAIN looking up A for susfasfasfasfdip.com - check that a DNS record exists for this domain; DNS problem: NXDOMAIN looking up AAAA for susfasfasfasfdip.com - check that a DNS record exists for this domain",
        "status": 400
      },
      "token": "hMO1V05jwWYYvjx-JKqqHBLX9j9R9rcCr1sobBMOXzY"
    }
  ]
}

```

3. Connection Timeout
```json

https://acme-staging-v02.api.letsencrypt.org/acme/authz/177930184/15532267594
{
  "identifier": {
    "type": "dns",
    "value": "test.mynepse.com"
  },
  "status": "invalid",
  "expires": "2025-01-05T06:12:46Z",
  "challenges": [
    {
      "type": "http-01",
      "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/177930184/15532267594/iWTemQ",
      "status": "invalid",
      "validated": "2024-12-29T06:12:51Z",
      "error": {
        "type": "urn:ietf:params:acme:error:connection",
        "detail": "27.34.67.17: Fetching http://test.mynepse.com/.well-known/acme-challenge/zzkbfMRpdWHkoavS0kxsY4o4ySVkFl-jpH7_vtKcdvk: Timeout during connect (likely firewall problem)",
        "status": 400
      },
      "token": "zzkbfMRpdWHkoavS0kxsY4o4ySVkFl-jpH7_vtKcdvk",
      "validationRecord": [
        {
          "url": "http://test.mynepse.com/.well-known/acme-challenge/zzkbfMRpdWHkoavS0kxsY4o4ySVkFl-jpH7_vtKcdvk",
          "hostname": "test.mynepse.com",
          "port": "80",
          "addressesResolved": [
            "27.34.67.17"
          ],
          "addressUsed": "27.34.67.17"
        }
      ]
    }
  ]
}
```

4. Connection Refused
```
https://acme-staging-v02.api.letsencrypt.org/acme/authz/177930184/15532308974
{
  "identifier": {
    "type": "dns",
    "value": "test3.mynepse.com"
  },
  "status": "invalid",
  "expires": "2025-01-05T06:21:58Z",
  "challenges": [
    {
      "type": "http-01",
      "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/177930184/15532308974/tEyIbw",
      "status": "invalid",
      "validated": "2024-12-29T06:22:02Z",
      "error": {
        "type": "urn:ietf:params:acme:error:connection",
        "detail": "94.130.221.189: Fetching http://test3.mynepse.com/.well-known/acme-challenge/FXFHdvetj89KxAvlqYlUWby9H3NCSwjDn-THw8QqAlo: Connection refused",
        "status": 400
      },
      "token": "FXFHdvetj89KxAvlqYlUWby9H3NCSwjDn-THw8QqAlo",
      "validationRecord": [
        {
          "url": "http://test3.mynepse.com/.well-known/acme-challenge/FXFHdvetj89KxAvlqYlUWby9H3NCSwjDn-THw8QqAlo",
          "hostname": "test3.mynepse.com",
          "port": "80",
          "addressesResolved": [
            "94.130.221.189"
          ],
          "addressUsed": "94.130.221.189"
        }
      ]
    }
  ]
}
-
```

### 5. Rate limit exceeded
Interesting thing about this error is that if I add new domain add add a combined certificate, the rate limit won't be applicable.
```
https://acme-v02.api.letsencrypt.org/acme/new-order
{
  "Server": "nginx",
  "Date": "Sun, 29 Dec 2024 06:43:23 GMT",
  "Content-Type": "application/problem+json",
  "Content-Length": "306",
  "Connection": "keep-alive",
  "Boulder-Requester": "2139716425",
  "Cache-Control": "public, max-age=0, no-cache",
  "Link": "<https://acme-v02.api.letsencrypt.org/directory>;rel=\"index\", <https://letsencrypt.org/docs/rate-limits>;rel=\"help\"",
  "Replay-Nonce": "LPSR-4-sxpaWDZScM4CZg7YEiYhGhHAKNN9ZCE7JUVZh0rbuNXg",
  "Retry-After": "123832"
}
{
  "type": "urn:ietf:params:acme:error:rateLimited",
  "detail": "too many certificates (5) already issued for this exact set of domains in the last 168h0m0s, retry after 2024-12-30 17:07:16 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-hostnames",
  "status": 429
}
```
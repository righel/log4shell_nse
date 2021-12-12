# log4shell NSE

## log4shell.nse
Injects a Huntress log4shell payload in HTTP requests described by JSON templates.
Results expire after 30 minutes.

**Sample usage**
```
$ nmap --script log4shell.nse --script-args id=<uuid> mode=huntress -p 80 localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-11 12:43 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000059s latency).

PORT   STATE SERVICE
80/tcp open  http
|_log4shell: Check https://log4shell.huntress.com/view/<uuid> for results.

Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```

**Options**
* `id`: Unique id linked with this scan.
* `mode`: Payload template, one of `huntress`, `canary_tokens` or `custom`.
* `payload`: Specify a custom payload, should include `%s` where the unique id related to this scan will be replaced.


**Examples**

* Huntress:
```
$ nmap --script log4shell.nse --script-args=id=<hash>,mode=huntress -p http* 127.0.0.1
```

* CanaryTokens:
```
$ nmap --script log4shell.nse --script-args=id=<hash>,mode=canary_tokens" -p http* 127.0.0.1
```

* Custom payload:
```
$ nmap --script log4shell.nse --script-args=id=<hash>,mode=custom,payload="jndi:dns:/%s.tracker.com" -p http* 127.0.0.1
```

References:
- https://log4shell.huntress.com/

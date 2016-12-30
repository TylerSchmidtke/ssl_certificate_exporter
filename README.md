# SSL Certificate Exporter

Prometheus exporter for SSL certificate metrics. This exporter is designed to scan network ranges to discover certificates on scanned hosts and retrieve the expiration time in days, namely for instances where you do not have a service discovery mechanism that Prometheus supports. If you do, I recommend using the [blackbox_exporter](https://github.com/prometheus/blackbox_exporter).

## Configuring, and running

### Docker
```
docker run tylerschmidtke/ssl_certificate_exporter --nets 127.0.0.1/32,127.0.1.1/32
```

### Running Locally
1. Install requirements:

    ```
    pip install -r requirements.txt
    ```

2. Run using your preferred method, I use [supervisord](http://supervisord.org/).

### Prometheus
Add a block to the `scrape_configs` of your prometheus.yml config file:

```
scrape_configs:
    
...
    
- job_name: ssl_certificate_exporter
  static_configs:
  - targets: ['example.com:9515']

...
```
### Flags

Name                 | Description
---------------------|------------
--nets               | Comma-separated list of networks to scan.
--port               | Port to listen on for web interface and telemetry. Default `9515`.
--ssl\_port          | Port to scan on remote hosts for SSL certificates. Default `443`.
--sleep              | Time to wait between scans in seconds. Default `43200` (12 hours). 
--timeout            | Timeout interval for SSL connections in seconds. Default `.5`.
--no\_dns            | Do not perform rDNS lookups.
--debug              | Debug level logging.


### Metrics

Name                          | Description
------------------------------|------------
ssl\_certificate\_days\_valid | Time in days that the certificate is valid.


### Labels
Name         | Description
-------------|------------
commonName   | Common Name on the certificate.
ipAddress    | IP address from which the certificate was received.
hostname     | Hostname for the scanned IP address if rDNS is available.
issuer       | Issuer of the certificate
serialNumber | Serial number of the certificate

### Caveats
Requires that the certificate is signed by a valid Certificate Authority.

### Suggestions?

Open an issue or PR if you have more suggestions or ideas about what to add.
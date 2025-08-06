FROM jasonish/suricata:latest
# Update Emerging Threats Open rules (or Pro if API key provided)
ARG ET_PRO_API_KEY=""
RUN if [ -n "$ET_PRO_API_KEY" ]; then \
      suricata-update --suricata-conf /etc/suricata/suricata.yaml --repo et/pro --apikey $ET_PRO_API_KEY; \
    else \
      suricata-update --suricata-conf /etc/suricata/suricata.yaml; fi && \
    suricata --build-info
ENTRYPOINT ["/usr/bin/suricata"]
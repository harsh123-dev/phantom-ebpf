FROM tiangolo/uwsgi-nginx-flask:python3.11

# Add the background worker beacon script.
COPY phantom-worker /usr/local/bin/phantom-worker
RUN chmod +x /usr/local/bin/phantom-worker

# Add the modified entrypoint wrapper.
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# Override entrypoint to launch both the worker and the original service.
ENTRYPOINT ["/usr/local/bin/start.sh"]
CMD []

FROM returntocorp/semgrep:1.78.0

# Non-root unprivileged execution
USER semgrep

WORKDIR /src

ENTRYPOINT ["semgrep"]
CMD ["scan", "--config=auto", "--json"]

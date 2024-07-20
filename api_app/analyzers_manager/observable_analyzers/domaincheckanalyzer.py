from domaincheck import domaincheck

result = domaincheck.main(
    ["google.com"], resolver="8.8.8.8", output_format="json", verbosity=4
)

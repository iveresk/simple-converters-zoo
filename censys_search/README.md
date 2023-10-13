# censys-search

Simple censys search tool by 1vere$k.

## Getting started

```
1. pip install censys
2. censys config
 - enter API_ID
 - enter Secret_Key
 ```

 ## Usage

 ```
 python3 censys_search.py -q "<Enter a query in Censys JSON format>" OPTIONAL[-p <pages_number> -o <output_file.txt>] 

 Default pages number equals 10. Every page = 200 IPs.

 Eample:

 python3 censys_search.py -q "services.software.product:'IIS' and autonomous_system.asn:'20485' and location.country:'Russia'" -p 10
 ```

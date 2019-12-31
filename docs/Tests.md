# Tests

If you want to run tests, you should:

- Change the following environment variables in the environment file based on the data you would like to test
    * TEST_TOKEN -> API key for testing purposes
    * TEST_JOB_ID
    * TEST_MD5
    * TEST_URL
    * TEST_IP
    * TEST_DOMAIN
    
- I didn't add to the project my test files because they are malware samples and I do not want people to use them in a wrong way. 
So, if you want to test files, you should add the following files to the folder `test_files`:
    * documento.pdf (to test PDF engines)
    * documento.rtf (to test RTF engines)
    * documento.doc (to test DOC engines)
    * file.exe (to test PE engines)
    * file.dll (to test DLL engines)
    * non_valid_pe.exe (to test non-valid PE)

    
Run:
`docker exec -ti intel_owl_uwsgi python3 manage.py test`
    

analyzerType="$1"
analyzersToExecute="$2"

testPath=""

case "$analyzerType" in
        "ip")
            testPath="tests.analyzers_manager.test_observable_scripts.IPAnalyzersTestCase.test_pipeline"
            ;;
        "url")
            testPath="tests.analyzers_manager.test_observable_scripts.URLAnalyzersTestCase.test_pipeline"
            ;;
        "domain")
            testPath="tests.analyzers_manager.test_observable_scripts.DomainAnalyzersTestCase.test_pipeline"
            ;;
        "hash")
            testPath="tests.analyzers_manager.test_observable_scripts.HashAnalyzersTestCase.test_pipeline"
            ;;
        "generic")
            testPath="tests.analyzers_manager.test_observable_scripts.GenericAnalyzersTestCase.test_pipeline"
            ;;
        "exe")
            testPath="tests.analyzers_manager.test_file_scripts.EXEAnalyzersTestCase.test_pipeline"
            ;;
        "dll")
            testPath="tests.analyzers_manager.test_file_scripts.DLLAnalyzersTestCase.test_pipeline"
            ;;
        "doc")
            testPath="tests.analyzers_manager.test_file_scripts.DocAnalyzersTestCase.test_pipeline"
            ;;
        "excel")
            testPath="tests.analyzers_manager.test_file_scripts.ExcelAnalyzersTestCase.test_pipeline"
            ;;
        "rtf")
            testPath="tests.analyzers_manager.test_file_scripts.RtfAnalyzersTestCase.test_pipeline"
            ;;            
        "pdf")
            testPath="tests.analyzers_manager.test_file_scripts.PDFAnalyzersTestCase.test_pipeline"
            ;;
        "html")
            testPath="tests.analyzers_manager.test_file_scripts.HTMLAnalyzersTestCase.test_pipeline"
            ;; 
        "js")
            testPath="tests.analyzers_manager.test_file_scripts.JSAnalyzersTestCase.test_pipeline"
            ;; 
        "apk")
            testPath="tests.analyzers_manager.test_file_scripts.APKAnalyzersTestCase.test_pipeline"
            ;;
        "pcap")
            testPath="tests.analyzers_manager.test_file_scripts.PCAPAnalyzersTestCase.test_pipeline"
            ;;
        "elf")
            testPath="tests.analyzers_manager.test_file_scripts.ELFAnalyzersTestCase.test_pipeline"
            ;;
        *)
            echo 'error' >&2
            exit 1
esac

docker exec -e TEST_ANALYZERS=$analyzersToExecute -it intelowl_uwsgi \
    python3 manage.py test $testPath
analyzerType="$1"
analyzersToExecute="$2"

testPath=""

case "$analyzerType" in
        "ip")
            testPath="tests.analyzers_manager.test_observable_scripts.IPAnalyzersTestCase.test_start_analyzers"
            ;;
        "url")
            testPath="tests.analyzers_manager.test_observable_scripts.URLAnalyzersTestCase.test_start_analyzers"
            ;;
        "domain")
            testPath="tests.analyzers_manager.test_observable_scripts.DomainAnalyzersTestCase.test_start_analyzers"
            ;;
        "hash")
            testPath="tests.analyzers_manager.test_observable_scripts.HashAnalyzersTestCase.test_start_analyzers"
            ;;
        "generic")
            testPath="tests.analyzers_manager.test_observable_scripts.GenericAnalyzersTestCase.test_start_analyzers"
            ;;
        "exe")
            testPath="tests.analyzers_manager.test_file_scripts.EXEAnalyzersTestCase.test_start_analyzers"
            ;;
        "dll")
            testPath="tests.analyzers_manager.test_file_scripts.DLLAnalyzersTestCase.test_start_analyzers"
            ;;
        "doc")
            testPath="tests.analyzers_manager.test_file_scripts.DocAnalyzersTestCase.test_start_analyzers"
            ;;
        "excel")
            testPath="tests.analyzers_manager.test_file_scripts.ExcelAnalyzersTestCase.test_start_analyzers"
            ;;
        "rtf")
            testPath="tests.analyzers_manager.test_file_scripts.RtfAnalyzersTestCase.test_start_analyzers"
            ;;            
        "pdf")
            testPath="tests.analyzers_manager.test_file_scripts.PDFAnalyzersTestCase.test_start_analyzers"
            ;;
        "html")
            testPath="tests.analyzers_manager.test_file_scripts.HTMLAnalyzersTestCase.test_start_analyzers"
            ;; 
        "js")
            testPath="tests.analyzers_manager.test_file_scripts.JSAnalyzersTestCase.test_start_analyzers"
            ;; 
        "apk")
            testPath="tests.analyzers_manager.test_file_scripts.APKAnalyzersTestCase.test_start_analyzers"
            ;;
        *)
            echo 'error' >&2
            exit 1
esac

docker exec -e TEST_ANALYZERS=$analyzersToExecute -it intelowl_uwsgi \
    python3 manage.py test $testPath
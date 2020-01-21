import logging

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.db.models import Q
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app import models, utilities, serializers
from api_app.script_analyzers import general
from intel_owl import settings

logger = logging.getLogger(__name__)


def redirect_to_login(request):
    response = redirect('/gui/query_database')
    return response


@api_view(['GET'])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def ask_analysis_availability(request):
    '''
    This is useful to avoid to repeat the same analysis multiple times.
    By default this API checks if there are already analysis related to the md5 in status "running"...
    ...or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it's highly probable that you won't get all...
    ...the results that you expect

    :parameter: md5: string, md5 of the sample or observable to look for
    :parameter: analyzers_needed: list, specify analyzers needed
    :parameter: [running_only]: check only for running analysis, default False, any value is True

    :return: 200 if ok with list of all analysis related to that md5, 500 if failed
    '''
    source = str(request.user)
    analyzers_needed_list = []
    try:
        data_received = request.query_params
        logger.info("received request from {}. Data:{}".format(source, dict(data_received)))

        if 'md5' not in data_received:
            return Response({"error": "800"},
                            status=status.HTTP_400_BAD_REQUEST)

        if 'analyzers_needed' not in data_received:
            return Response({"error": "801"},
                            status=status.HTTP_400_BAD_REQUEST)

        if 'analyzers_needed' in data_received:
            analyzers_needed_list = data_received['analyzers_needed'].split(',')

        running_only = False
        if 'running_only' in data_received:
            running_only = True

        md5 = data_received['md5']

        if running_only:
            statuses_to_check = ["running"]
        else:
            statuses_to_check = ["running", "reported_without_fails"]
        query = Q(md5=md5) & Q(status__in=statuses_to_check) & Q(analyzers_to_execute__contains=analyzers_needed_list)
        last_job_for_md5_set = models.Job.objects.filter(query).order_by('-received_request_time')
        if last_job_for_md5_set:
            last_job_for_md5 = last_job_for_md5_set[0]
            response_dict = {"status": last_job_for_md5.status, "job_id": str(last_job_for_md5.id),
                             "analyzers_to_execute": last_job_for_md5.analyzers_to_execute}
        else:
            response_dict = {"status": "not_available"}

        logger.debug(response_dict)

        return Response(response_dict,
                        status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("ask_analysis_availability requester:{} error:{}".format(source, e))
        return Response({"error": "error in ask_analysis_availability. Check logs"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def send_analysis_request(request):
    '''
    This API allows to start a Job related to a file or an observable

    data_received parameters:
    :parameter: is_sample: is a sample (file) or an observable (domain, ip, ...)
    :parameter: md5: string, md5 of the item to analyze
    :parameter: [file]: binary, required if is_sample=True, the binary
    :parameter: [file_mimetype]: string, required if is_sample=True, the binary mimetype
    :parameter: [file_name]: string, optional if is_sample=True, the binary name
    :parameter: [observable_name]: string, required if is_sample=False, the observable value
    :parameter: [observable_classification]: string, required if is_sample=False, (domain, ip, ...)
    :parameter: analyzers_requested: list of requested analyzer to run, before filters
    :parameter: [force_privacy]: boolean, default False, enable it if you want to avoid to run analyzers with privacy issues
    :parameter: [disable_external_analyzers]: boolean, default False, enable it if you want to exclude external analyzers

    :return: 202 if accepted, 500 if failed
    '''
    source = str(request.user)
    warnings = []
    try:
        data_received = request.data
        logger.info("received request from {}. Data:{}".format(source, dict(data_received)))

        params = {
            'source': source
        }

        serializer = serializers.JobSerializer(data=data_received)
        if serializer.is_valid():
            serialized_data = serializer.validated_data
            logger.info("serialized_data: {}".format(serialized_data))

            # some values are mandatory only in certain cases
            if serialized_data['is_sample']:
                if 'file' not in data_received:
                    return Response({"error": "810"},
                                    status=status.HTTP_400_BAD_REQUEST)
                if 'file_mimetype' not in data_received:
                    return Response({"error": "811"},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                if 'observable_name' not in data_received:
                    return Response({"error": "812"},
                                    status=status.HTTP_400_BAD_REQUEST)
                if 'observable_classification' not in data_received:
                    return Response({"error": "813"},
                                    status=status.HTTP_400_BAD_REQUEST)

            # we need to clean the list of request analyzers, based on configuration data
            analyzers_config = utilities.get_analyzer_config()
            cleaned_analyzer_list = utilities.filter_analyzers(serialized_data, analyzers_config, warnings)
            params['analyzers_to_execute'] = cleaned_analyzer_list
            if len(cleaned_analyzer_list) < 1:
                logger.info("after the filter, no analyzers can be run. Try with other analyzers")
                return Response({"error": "814"},
                                status=status.HTTP_400_BAD_REQUEST)

            # save the arrived data plus new params into a new job object
            serializer.save(**params)
            job_id = serializer.data.get('id', '')
            md5 = serializer.data.get('md5', '')
            logger.info("new job_id {} for md5 {}".format(job_id, md5))
            if not job_id:
                return Response({"error": "815"},
                                status=status.HTTP_400_BAD_REQUEST)

        else:
            error_message = "serializer validation failed: {}".format(serializer.errors)
            logger.info(error_message)
            return Response(error_message,
                            status=status.HTTP_400_BAD_REQUEST)

        is_sample = serializer.data.get('is_sample', '')
        general.start_analyzers(params['analyzers_to_execute'], analyzers_config, job_id, md5, is_sample, logger)

        response_dict = {"status": "accepted", "job_id": job_id, "warnings": warnings,
                         "analyzers_running": cleaned_analyzer_list}

        logger.debug(response_dict)

        return Response(response_dict,
                        status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("receive_analysis_request requester:{} error:{}".format(source, e))
        return Response({"error": "error in send_analysis_request. Check logs"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def ask_analysis_result(request):
    '''
    This API allows to retrieve the status and results of a specific Job based on its ID

    :parameter: job_id: integer, Job ID

    :return: 200 if ok, 500 if failed
    '''
    source = str(request.user)
    try:
        data_received = request.query_params
        logger.info("received request from {}. Data:{}".format(source, dict(data_received)))

        if 'job_id' not in data_received:
            return Response({"error": "820"},
                            status=status.HTTP_400_BAD_REQUEST)

        job_id = data_received['job_id']
        try:
            job = models.Job.objects.get(id=job_id)
        except models.Job.DoesNotExist:
            response_dict = {"status": "not_available"}
        else:
            response_dict = {"status": job.status, "results": job.analysis_reports, "job_id": str(job.id)}
            # adding elapsed time
            finished_analysis_time = getattr(job, "finished_analysis_time", "")
            if not finished_analysis_time:
                finished_analysis_time = utilities.get_now()
            elapsed_time = finished_analysis_time - job.received_request_time
            seconds = elapsed_time.total_seconds()
            response_dict['elapsed_time_in_seconds'] = seconds

        logger.debug(response_dict)

        return Response(response_dict,
                        status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("ask_analysis_result requester:{} error:{}".format(source, e))
        return Response({"error": "error in ask_analysis_result. Check logs"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def verify_login(request):
    username = request.POST['username']
    password = request.POST['password']
    uri = request.POST['uri']
    if not uri:
        uri = "/gui/query_database"
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        # Redirect to a success page.
        return redirect(uri)
    else:
        # Return an 'invalid login' error message.
        context = dict()
        context['next'] = uri
        context['login_failed'] = "login failed"
        context['debug'] = settings.DEBUG
        return render(request, 'login.html', context)


@login_required
def logout_request(request):
    logout(request)
    # Redirect to a success page.
    return redirect("/gui/login")


@login_required
@api_view(['GET', 'POST'])
def query_database(request):
    try:

        context = {}
        context['post'] = False

        if request.method == "POST":
            data_received = request.POST.dict()
            logger.info("requested data for these values: {}".format(data_received))
            context['post'] = True
            params = {}

            database_fields = ['id', 'md5', 'source', 'file_name', 'observable_name', 'status']
            for database_field in database_fields:
                sent_value = data_received.get(database_field, None)
                if sent_value:
                    params[database_field] = sent_value

            if data_received.get('count', False):
                context['only_count'] = True
                count = models.Job.objects.filter(**params).count()
                context['count'] = str(count)

            else:
                context['only_count'] = False
                # default limit
                limit = 10
                # set limit on query
                if data_received.get('limit', None):
                    try:
                        limit = int(data_received['limit'])
                    except ValueError:
                        return Response({"error": "limit value is not an integer"},
                                        status=status.HTTP_400_BAD_REQUEST)
                jobs = models.Job.objects.filter(**params).order_by('-received_request_time')[:limit]
                context['jobs'] = jobs
                context['count'] = len(jobs)

        context['STATIC_URL'] = settings.STATIC_URL
        context['debug'] = settings.DEBUG
        return render(request, 'query_database.html', context)

    except Exception as e:
        str_err = str(e)
        logger.exception(str_err)
        return Response({"error": str_err},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
@api_view(['GET'])
def query_database_json(request, job_id):
    try:
        job = models.Job.objects.filter(id=job_id).values()
        if job:
            return JsonResponse(job[0])
        else:
            return Response({"error": "not found job with id {}".format(job_id)},
                            status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        str_err = str(e)
        logger.exception(str_err)
        return Response({"error": str_err},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

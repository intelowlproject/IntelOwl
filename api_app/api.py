import logging

from api_app import models, serializers, utilities
from .script_analyzers import general

from django.http import JsonResponse
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.views.decorators.csrf import ensure_csrf_cookie
from django.db.models import Q
from rest_framework import status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated


logger = logging.getLogger(__name__)


""" REST API endpoints """


@api_view(["GET"])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def ask_analysis_availability(request):
    """
    This is useful to avoid repeating the same analysis multiple times.
    By default this API checks if there are existing analysis related to the md5 in
    status "running" or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it is
    highly probable that you won't get all the results that you expect

    :param md5: string
        md5 of the sample or observable to look for
    :param [analyzers_needed]: list
        specify analyzers needed. It is requires this or run_all_available_analyzers
    :param [run_all_available_analyzers]: bool
        if we are looking for an analysis executed with this flag set
    :param [running_only]: bool
        check only for running analysis, default False, any value is True

    :return 200:
        if ok with list of all analysis related to that md5
    :return 500:
        if failed
    """
    source = str(request.user)
    analyzers_needed_list = []
    run_all_available_analyzers = False
    try:
        data_received = request.query_params
        logger.info(
            f"ask_analysis_availability received request from {source}."
            f"Data: {dict(data_received)}"
        )

        if "md5" not in data_received:
            return JsonResponse({"error": "800"}, status=status.HTTP_400_BAD_REQUEST)

        if (
            "analyzers_needed" not in data_received
            and "run_all_available_analyzers" not in data_received
        ):
            return JsonResponse({"error": "801"}, status=status.HTTP_400_BAD_REQUEST)

        if "run_all_available_analyzers" in data_received:
            if data_received["run_all_available_analyzers"]:
                run_all_available_analyzers = True
        if not run_all_available_analyzers:
            if "analyzers_needed" not in data_received:
                return JsonResponse(
                    {"error": "802"}, status=status.HTTP_400_BAD_REQUEST
                )
            if isinstance(data_received["analyzers_needed"], list):
                analyzers_needed_list = data_received["analyzers_needed"].split(",")

        running_only = False
        if "running_only" in data_received:
            running_only = True

        md5 = data_received["md5"]

        if running_only:
            statuses_to_check = ["running"]
        else:
            statuses_to_check = ["running", "reported_without_fails"]

        if run_all_available_analyzers:
            query = (
                Q(md5=md5)
                & Q(status__in=statuses_to_check)
                & Q(run_all_available_analyzers=True)
            )
        else:
            query = (
                Q(md5=md5)
                & Q(status__in=statuses_to_check)
                & Q(analyzers_to_execute__contains=analyzers_needed_list)
            )

        last_job_for_md5_set = models.Job.objects.filter(query).order_by(
            "-received_request_time"
        )
        if last_job_for_md5_set:
            last_job_for_md5 = last_job_for_md5_set[0]
            response_dict = {
                "status": last_job_for_md5.status,
                "job_id": str(last_job_for_md5.id),
                "analyzers_to_execute": last_job_for_md5.analyzers_to_execute,
            }
        else:
            response_dict = {"status": "not_available"}

        logger.debug(response_dict)

        return JsonResponse(response_dict, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"ask_analysis_availability requester:{source} error:{e}.")
        return JsonResponse(
            {"error": "error in ask_analysis_availability. Check logs."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def send_analysis_request(request):
    """
    This endpoint allows to start a Job related to a file or an observable

    :param is_sample: bool
        is a sample (file) or an observable (domain, ip, ...)
    :param md5: string
        md5 of the item to analyze
    :param [file]: binary
        required if is_sample=True, the binary
    :param [file_mimetype]: string
        optional, the binary mimetype, calculated by default
    :param [file_name]: string
        optional if is_sample=True, the binary name
    :param [observable_name]: string
        required if is_sample=False, the observable value
    :param [observable_classification]: string
        required if is_sample=False, (domain, ip, ...)
    :param [analyzers_requested]: list
        list of requested analyzer to run, before filters
    :param [tags_id]: list<int>
        list of id's of tags to apply to job
    :param [run_all_available_analyzers]: bool
        default False
    :param [force_privacy]: bool
        default False,
        enable it if you want to avoid to run analyzers with privacy issues
    :param [disable_external_analyzers]: bool
        default False,
        enable it if you want to exclude external analyzers
    :param [test]: bool
        disable analysis for API testing

    :return 202:
        if accepted
    :return 500:
        if failed
    """
    source = str(request.user)
    warnings = []
    try:
        data_received = request.data
        logger.info(
            f"send_analysis_request received request from {source}."
            f"Data:{dict(data_received)}."
        )

        test = data_received.get("test", False)

        params = {"source": source}

        serializer = serializers.JobSerializer(data=data_received)
        if serializer.is_valid():
            serialized_data = serializer.validated_data
            logger.info(f"serialized_data: {serialized_data}")

            # some values are mandatory only in certain cases
            if serialized_data["is_sample"]:
                if "file" not in data_received:
                    return JsonResponse(
                        {"error": "810"}, status=status.HTTP_400_BAD_REQUEST
                    )
                if "file_mimetype" not in data_received:
                    serialized_data["file_mimetype"] = utilities.calculate_mimetype(
                        data_received["file"], data_received.get("file_name", "")
                    )
            else:
                if "observable_name" not in data_received:
                    return JsonResponse(
                        {"error": "812"}, status=status.HTTP_400_BAD_REQUEST
                    )
                if "observable_classification" not in data_received:
                    return JsonResponse(
                        {"error": "813"}, status=status.HTTP_400_BAD_REQUEST
                    )

            # we need to clean the list of requested analyzers,
            # ... based on configuration data
            analyzers_config = utilities.get_analyzer_config()
            run_all_available_analyzers = serialized_data.get(
                "run_all_available_analyzers", False
            )
            analyzers_requested = serialized_data.get("analyzers_requested", [])
            if run_all_available_analyzers:
                if analyzers_requested:
                    logger.info(
                        """either you specify a list of requested analyzers or the
                         'run_all_available_analyzers' parameter, not both"""
                    )
                    return JsonResponse(
                        {"error": "816"}, status=status.HTTP_400_BAD_REQUEST
                    )
                # just pick all available analyzers
                analyzers_requested = [
                    analyzer_name for analyzer_name in analyzers_config
                ]
            cleaned_analyzer_list = utilities.filter_analyzers(
                serialized_data,
                analyzers_requested,
                analyzers_config,
                warnings,
                run_all=run_all_available_analyzers,
            )
            params["analyzers_to_execute"] = cleaned_analyzer_list
            if len(cleaned_analyzer_list) < 1:
                logger.info(
                    """after the filter, no analyzers can be run.
                     Try with other analyzers"""
                )
                return JsonResponse(
                    {"error": "814"}, status=status.HTTP_400_BAD_REQUEST
                )

            # save the arrived data plus new params into a new job object
            serializer.save(**params)
            job_id = serializer.data.get("id", "")
            md5 = serializer.data.get("md5", "")
            logger.info("new job_id {job_id} for md5 {md5}")
            if not job_id:
                return JsonResponse(
                    {"error": "815"}, status=status.HTTP_400_BAD_REQUEST
                )

        else:
            error_message = f"serializer validation failed: {serializer.errors}"
            logger.info(error_message)
            return JsonResponse(error_message, status=status.HTTP_400_BAD_REQUEST)

        is_sample = serializer.data.get("is_sample", "")
        if not test:
            general.start_analyzers(
                params["analyzers_to_execute"], analyzers_config, job_id, md5, is_sample
            )

        response_dict = {
            "status": "accepted",
            "job_id": job_id,
            "warnings": warnings,
            "analyzers_running": cleaned_analyzer_list,
        }

        logger.debug(response_dict)

        return JsonResponse(response_dict, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"receive_analysis_request requester:{source} error:{e}.")
        return JsonResponse(
            {"error": "error in send_analysis_request. Check logs"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def ask_analysis_result(request):
    """
    Endpoint to retrieve the status and results of a specific Job based on its ID

    :param job_id: integer
        Job ID
    :return 200:
        if ok
    :return 500:
        if failed
    """
    source = str(request.user)
    try:
        data_received = request.query_params
        logger.info(
            f"""
            ask_analysis_result received request from {source}.
             Data:{dict(data_received)}
            """
        )
        if "job_id" not in data_received:
            return JsonResponse({"error": "820"}, status=status.HTTP_400_BAD_REQUEST)

        job_id = data_received["job_id"]
        try:
            job = models.Job.objects.get(id=job_id)
        except models.Job.DoesNotExist:
            response_dict = {"status": "not_available"}
        else:
            response_dict = {
                "status": job.status,
                "results": job.analysis_reports,
                "job_id": str(job.id),
            }
            # adding elapsed time
            finished_analysis_time = getattr(job, "finished_analysis_time", "")
            if not finished_analysis_time:
                finished_analysis_time = utilities.get_now()
            elapsed_time = finished_analysis_time - job.received_request_time
            seconds = elapsed_time.total_seconds()
            response_dict["elapsed_time_in_seconds"] = seconds

        logger.debug(response_dict)

        return JsonResponse(response_dict, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"ask_analysis_result requester:{source} error:{e}")
        return JsonResponse(
            {"error": "error in ask_analysis_result. Check logs"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@ensure_csrf_cookie
def obtain_user_token(request):
    """
    REST endpoint to obtain user auth token via authentication

    :param email: string
        email address of registered user\n
    :param password: string
        password of registered user

    :return 202:
        if accepted
    :return 404:
        if failed
    """
    try:
        email = request.data["email"]
        logger.info(f"obtain_user_token received request for {email}.")
        password = request.data["password"]
        u = User.objects.get(email=email)
        user = authenticate(username=u.username, password=password)
        if user:
            logger.debug(f"obtain_user_token token created for {email}.")
            token, _created = Token.objects.get_or_create(user=user)
            return JsonResponse(
                {"token": str(token.key)}, status=status.HTTP_202_ACCEPTED
            )
        raise Exception("No such user exists.")

    except Exception as e:
        logger.exception(f"obtain_user_token exception: {e}.")
        return JsonResponse({"error": e}, status=status.HTTP_404_NOT_FOUND)


@api_view(["POST"])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def perform_logout(request):
    """
    REST endpoint to delete/invalidate user auth token and logout user.
    Requires authentication.

    :return 200:
        if ok
    :return 400:
        if failed
    """
    try:
        logger.info(f"perform_logout received request from {str(request.user)}")
        request.auth.delete()  # remove/invalidate the token on logout
        return JsonResponse({"status": "You've been logged out."})
    except Exception as e:
        str_err = str(e)
        logger.exception(f"perform_logout exception: {str_err}")
        return JsonResponse({"error": str_err}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
@ensure_csrf_cookie
def get_user_info(request):
    """
    To fetch user detail like username and user ID.
    Requires authentication.

    :return 200:
        if ok
    :return 400:
        if failed
    """
    try:
        logger.info(f"get_user_info received request from {str(request.user)}.")
        return JsonResponse({"id": request.user.id, "username": request.user.username,})
    except Exception as e:
        str_err = str(e)
        logger.exception(f"get_user_info exception: {str_err}.")
        return JsonResponse({"error": str_err}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def get_analyzer_configs(request):
    """
    get the uploaded analyzer configuration,
    can be useful if you want to choose the analyzers programmatically

    :return 200:
        if ok
    :return 500:
        if failed
    """
    try:
        logger.info(f"get_analyzer_configs received request from {str(request.user)}.")

        analyzers_config = utilities.get_analyzer_config()

        return JsonResponse(analyzers_config)

    except Exception as e:
        logger.exception(
            f"get_analyzer_configs requester:{str(request.user)} error:{e}."
        )
        return JsonResponse(
            {"error": "error in get_analyzer_configs. Check logs."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class JobViewSet(viewsets.ReadOnlyModelViewSet):
    """
    REST endpoint to fetch list of jobs or retrieve a job with job ID.
    Requires authentication.

    :methods_allowed:
        GET, OPTIONS

    :return 200:
        if ok
    :return 404:
        if not found
    :return 405:
        if wrong HTTP method
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = models.Job.objects.all()
    serializer_class = serializers.JobSerializer

    def list(self, request):
        queryset = (
            models.Job.objects.order_by("-received_request_time")
            .defer("analysis_reports", "errors")
            .all()
        )
        serializer = serializers.JobListSerializer(queryset, many=True)
        return Response(serializer.data)


class TagViewSet(viewsets.ModelViewSet):
    """
    REST endpoint to pefrom CRUD operations on Job tags.
    Requires authentication.

    :methods_allowed:
        GET, POST, PUT, DELETE, OPTIONS

    :return 200:
        if ok
    :return 404:
        if not found
    :return 405:
        if wrong HTTP method
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = models.Tag.objects.all()
    serializer_class = serializers.TagSerializer

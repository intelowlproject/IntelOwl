import logging

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from api_app import models
from intel_owl import settings


logger = logging.getLogger(__name__)


""" GUI endpoints """


def redirect_to_login(request):
    response = redirect("/gui/query_database")
    return response


def verify_login(request):
    username = request.POST["username"]
    password = request.POST["password"]
    uri = "/gui/query_database"
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        # Redirect to a success page.
        return redirect(uri)
    # Return an 'invalid login' error message.
    context = dict()
    context["next"] = uri
    context["login_failed"] = "login failed"
    context["debug"] = settings.DEBUG
    return render(request, "login.html", context)


@login_required
def logout_request(request):
    logout(request)
    # Redirect to a success page.
    return redirect("/gui/login")


@login_required
@api_view(["GET", "POST"])
def query_database(request):
    try:

        context = {}
        context["post"] = False

        if request.method == "POST":
            data_received = request.POST.dict()
            logger.info(f"requested data for these values: {data_received}.")
            context["post"] = True
            params = {}

            database_fields = [
                "id",
                "md5",
                "source",
                "file_name",
                "observable_name",
                "status",
            ]
            for database_field in database_fields:
                sent_value = data_received.get(database_field, None)
                if sent_value:
                    params[database_field] = sent_value

            if data_received.get("count", False):
                context["only_count"] = True
                count = models.Job.objects.filter(**params).count()
                context["count"] = str(count)

            else:
                context["only_count"] = False
                # default limit
                limit = 10
                # set limit on query
                if data_received.get("limit", None):
                    try:
                        limit = int(data_received["limit"])
                    except ValueError:
                        return Response(
                            {"error": "limit value is not an integer."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                jobs = models.Job.objects.filter(**params).order_by(
                    "-received_request_time"
                )[:limit]
                context["jobs"] = jobs
                context["count"] = len(jobs)

        context["STATIC_URL"] = settings.STATIC_URL
        context["debug"] = settings.DEBUG
        return render(request, "query_database.html", context)

    except Exception as e:
        str_err = str(e)
        logger.exception(str_err)
        return Response(
            {"error": str_err}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

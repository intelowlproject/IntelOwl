# from django.shortcuts import render
# from rest_framework import serializers as rfs
from rest_framework import viewsets

from api_app.analyzers_manager.serializers import AnalyzerSerializer


class AnalyzerViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AnalyzerSerializer

from rest_framework import serializers
from api_app.models import Job, Tag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = "__all__"


class JobSerializer(serializers.ModelSerializer):
    tags = TagSerializer(many=True, read_only=True)
    tags_id = serializers.PrimaryKeyRelatedField(
        many=True, write_only=True, queryset=Tag.objects.all()
    )

    class Meta:
        model = Job
        fields = "__all__"
        extra_kwargs = {"tags": {"required": False}}

    def create(self, validated_data):
        tags = validated_data.pop("tags_id", None)
        job = Job.objects.create(**validated_data)
        if tags:
            job.tags.set(tags)

        return job

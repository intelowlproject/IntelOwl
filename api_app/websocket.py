import logging

from channels.generic.websocket import JsonWebsocketConsumer

from api_app.models import Job
from api_app.serializers import JobSerializer

logger = logging.getLogger(__name__)


class JobConsumer(JsonWebsocketConsumer):
    def connect(self):
        user = self.scope["user"]
        job_id = self.scope["url_route"]["kwargs"]["job_id"]
        logger.info(f"user: {user} requested the analysis for the job {job_id}")
        self.accept()
        job = Job.objects.get(id=job_id)
        job_serializer = JobSerializer(job)
        job_data = job_serializer.data
        logger.debug(f"job data: {job_data}")
        self.send_json(content=job_data)

    def disconnect(self):
        user = self.scope["user"]
        logger.debug(f"user {user} disconnected!")
        self.close()

    def receive_json(self, content):
        logger.info("websocket receive!")
        user = self.scope["user"]
        logger.warning(
            f"user {user} send {content} to the websocket, this shouldn't happen"
        )


# sto metodo deve essere usato in altre parti del codice (direi alla fine del job)
# per accedere alla websocket giusta su cui inviare il risultato:
# channel_layer = get_channel_layer()
# await channel_layer.send("channel_name", {
#     "type": "chat.message",
#     "text": "Hello there!",
# })

# nell'esempio della doc si salvano i canali disponibili (le ws aperte) sul db:
# https://channels.readthedocs.io/en/latest/topics/channel_layers.html?highlight=get_channel_layer#single-channels

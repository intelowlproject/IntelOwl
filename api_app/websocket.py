import json
import logging

from channels.generic.websocket import WebsocketConsumer

logger = logging.getLogger(__name__)


class JobConsumer(WebsocketConsumer):
    def connect(self):
        logger.debug("websocket connect!")
        job_id = self.scope["url_route"]["kwargs"]["job_id"]
        user = self.scope["user"]
        logger.debug(f"this is the job id: {job_id}")
        logger.debug(f"user: {user}")
        self.accept()

    def disconnect(self):
        logger.debug("websocket disconnect!")
        # self.send(bytes_data="disconnect request received")
        self.close()

    # Receive message from WebSocket
    def receive(self):
        logger.debug("websocket receive!")
        self.send(text_data=json.dumps({"message": "it's working"}))
        # TODO: non so se viene inviato sempre almeno un messaggio.
        # in ogni caso quando uno va ad aprire un job vecchio viene usata la websocket
        # (in frontend non può sapere se è running o no)
        # e bisognerà gestire la casistica reportando subito il job.
        # nel caso in cui l'analisi sia appena partita e il job è running va detto
        # si fa un check sul db e si ritorna o lo status se è running o tutto il job


# sto metodo deve essere usato in altre parti del codice (direi alla fine del job)
# per accedere alla websocket giusta su cui inviare il risultato:
# channel_layer = get_channel_layer()
# await channel_layer.send("channel_name", {
#     "type": "chat.message",
#     "text": "Hello there!",
# })

# nell'esempio della doc si salvano i canali disponibili (le ws aperte) sul db:
# https://channels.readthedocs.io/en/latest/topics/channel_layers.html?highlight=get_channel_layer#single-channels

"""
Celery package
"""
from celery import Celery

app = Celery("python_test", broker_url="amqp://guest:guest@localhost:5672")


@app.task
def add(first_addend, second_addend):
    """
    Add two numbers together.
    :param first_addend: int
    :param second_addend: int
    :return: int
    """
    return first_addend + second_addend

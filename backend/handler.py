import boto3
import json
import logging
import time

from datetime import datetime


logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


def hello(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": event
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response


def ping(event, context):
    dynamodb = boto3.resource("dynamodb")

    body = {
        "message": f"Hola Amigo, pong - {datetime.utcnow()}!",
        "input": event
    }

    logger.info(f"Ping requested, ts: {datetime.utcnow()}")

    table = dynamodb.Table("serverless-chat_Messages")
    timestamp = int(time.time())
    table.put_item(
        Item={
            "Room": "general",
            "Index": 0,
            "Timestamp": timestamp,
            "Username": "ping-user",
            "Content": "Ping!"
        }
    )
    dynamodb = boto3.resource("dynamodb")

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response

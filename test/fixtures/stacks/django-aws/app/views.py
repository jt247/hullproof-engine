from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import anthropic
import boto3


@login_required
def ask(request):
    table = boto3.resource('dynamodb').Table('notes')
    return JsonResponse({'ok': bool(anthropic) and bool(table)})

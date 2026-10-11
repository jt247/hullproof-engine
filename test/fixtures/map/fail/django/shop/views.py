import json
import requests
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from .models import Note, User, Item


@csrf_exempt
@require_POST
def create_note(request):
    data = json.loads(request.body)
    Note.objects.create(title=data['title'], owner_id=data['owner'])
    return JsonResponse({'ok': True})


def export_users(request):
    return JsonResponse(list(User.objects.values('id', 'email')), safe=False)


@login_required
@require_POST
def delete_note(request, pk):
    Note.objects.filter(pk=pk).delete()
    return JsonResponse({'ok': True})


@login_required
@require_POST
def set_role(request):
    data = json.loads(request.body)
    User.objects.filter(pk=data['id']).update(role=data['role'])
    return JsonResponse({'ok': True})


@require_POST
def login_view(request):
    return HttpResponseRedirect(request.GET.get('next'))


@csrf_exempt
@require_POST
def pay_hook(request):
    ok = verify_signature(request.body, request.headers.get('X-Pay-Signature'))
    if not ok:
        print('bad signature')
    event = json.loads(request.body)
    User.objects.filter(pk=event['account']).update(paid=True)
    return JsonResponse({'received': True})


@login_required
@require_POST
def import_url(request):
    page = requests.get(json.loads(request.body)['url'])
    return JsonResponse({'text': page.text})


@login_required
@require_POST
def upload(request):
    f = request.FILES['file']
    with open('uploads/' + f.name, 'wb') as out:
        out.write(f.read())
    return JsonResponse({'ok': True})


@login_required
def items(request):
    limit = int(request.GET.get('limit', 50))
    return JsonResponse(list(Item.objects.filter(owner=request.user)[:limit].values('id', 'name')), safe=False)

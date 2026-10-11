import json
import uuid
import requests
from urllib.parse import urlparse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit
from .forms import NoteForm, RoleForm, ImportForm
from .models import Note, User, Item
from .audit import record_audit

ALLOWED_HOSTS = {'example.com'}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_TYPES = {'image/png', 'image/jpeg'}


@login_required
@require_POST
def create_note(request):
    form = NoteForm(json.loads(request.body))
    if not form.is_valid():
        return HttpResponseBadRequest()
    Note.objects.create(title=form.cleaned_data['title'], owner=request.user)
    return JsonResponse({'ok': True})


@login_required
def export_users(request):
    return JsonResponse(list(User.objects.filter(pk=request.user.pk).values('id', 'email')), safe=False)


@login_required
@require_POST
def delete_note(request, pk):
    Note.objects.filter(pk=pk, owner=request.user).delete()
    return JsonResponse({'ok': True})


@login_required
@user_passes_test(lambda u: u.is_staff)
@require_POST
def set_role(request):
    form = RoleForm(json.loads(request.body))
    if not form.is_valid():
        return HttpResponseBadRequest()
    User.objects.filter(pk=form.cleaned_data['id']).update(role=form.cleaned_data['role'])
    record_audit(actor=request.user.pk, action='set_role', target=form.cleaned_data['id'])
    return JsonResponse({'ok': True})


@ratelimit(key='ip', rate='10/m')
@require_POST
def login_view(request):
    target = request.GET.get('next', '/')
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=ALLOWED_HOSTS):
        target = '/'
    return HttpResponseRedirect(target)


@csrf_exempt
@require_POST
def pay_hook(request):
    ok = verify_signature(request.body, request.headers.get('X-Pay-Signature'))
    if not ok:
        return HttpResponseBadRequest()
    event = json.loads(request.body)
    User.objects.filter(pk=event['account']).update(paid=True)
    return JsonResponse({'received': True})


@login_required
@require_POST
def import_url(request):
    form = ImportForm(json.loads(request.body))
    if not form.is_valid() or urlparse(form.cleaned_data['url']).hostname not in ALLOWED_HOSTS:
        return HttpResponseBadRequest()
    page = requests.get(form.cleaned_data['url'])
    return JsonResponse({'text': page.text})


@login_required
@require_POST
def upload(request):
    f = request.FILES['file']
    if f.size > MAX_UPLOAD_BYTES:
        return HttpResponseBadRequest()
    if f.content_type not in ALLOWED_TYPES:
        return HttpResponseBadRequest()
    with open('uploads/' + str(uuid.uuid4()), 'wb') as out:
        out.write(f.read())
    return JsonResponse({'ok': True})


@login_required
def items(request):
    limit = min(int(request.GET.get('limit', 50)), 100)
    return JsonResponse(list(Item.objects.filter(owner=request.user)[:limit].values('id', 'name')), safe=False)

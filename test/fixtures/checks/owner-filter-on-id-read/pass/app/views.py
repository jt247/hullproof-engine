def note(request, pk):
    note = Note.objects.get(pk=request.GET["id"], owner=request.user)
    return JsonResponse(note)

def note(request, pk):
    note = Note.objects.get(pk=request.GET["id"])
    return JsonResponse(note)

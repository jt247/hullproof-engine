<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreNoteRequest;
use App\Models\Note;

class NoteController extends Controller
{
    public function store(StoreNoteRequest $request)
    {
        $note = $request->user()->notes()->create($request->validated());

        return response()->json($note);
    }

    public function destroy(Note $note)
    {
        $this->authorize('delete', $note);
        $note->delete();

        return response()->noContent();
    }
}

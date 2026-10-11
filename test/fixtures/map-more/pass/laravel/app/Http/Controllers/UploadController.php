<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UploadController extends Controller
{
    public function store(Request $request)
    {
        $request->validate(['file' => 'required|file|mimes:png,jpg|max:5120']);
        $request->file('file')->store('uploads');

        return response()->noContent(201);
    }
}

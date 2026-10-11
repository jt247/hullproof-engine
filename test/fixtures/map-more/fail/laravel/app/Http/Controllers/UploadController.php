<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UploadController extends Controller
{
    public function store(Request $request)
    {
        $file = $request->file('file');
        $file->move(public_path('uploads'), $file->getClientOriginalName());

        return response()->noContent(201);
    }
}

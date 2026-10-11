<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class ImportController extends Controller
{
    public function store(Request $request)
    {
        $page = Http::get($request->input('url'))->body();

        return $page;
    }
}

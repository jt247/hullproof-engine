<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class ImportController extends Controller
{
    public function store(Request $request)
    {
        $url = $request->validate(['url' => 'required|url'])['url'];
        abort_unless(in_array(parse_url($url, PHP_URL_HOST), config('app.allowed_hosts'), true), 400);

        return Http::get($url)->body();
    }
}

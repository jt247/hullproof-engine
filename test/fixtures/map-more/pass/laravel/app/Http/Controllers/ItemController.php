<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ItemController extends Controller
{
    public function index(Request $request)
    {
        $limit = min((int) $request->query('limit', 50), 100);

        return $request->user()->items()->limit($limit)->get();
    }
}

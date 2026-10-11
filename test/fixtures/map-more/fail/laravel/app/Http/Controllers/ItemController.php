<?php

namespace App\Http\Controllers;

use App\Models\Item;
use Illuminate\Http\Request;

class ItemController extends Controller
{
    public function index(Request $request)
    {
        $limit = (int) $request->query('limit', 50);

        return Item::query()->limit($limit)->get();
    }
}

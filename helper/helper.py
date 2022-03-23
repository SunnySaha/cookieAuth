def get_serialized_credential(data) -> dict:
    return {
        'email': data['email'],
        'password': data['password']
    }


def item_schema(item) -> dict:
    return {
        "id": str(item["_id"]),
        "name": item["name"],
        "price": item["price"],
        "is_available": item["is_available"],
        "tax": item["tax"],
        "is_tax_apply": item["is_tax_apply"],
    }


def single_item(item) -> dict:
    return {
        "name": item["name"],
        "price": item["price"],
        "is_available": item["is_available"],
        "tax": item["tax"],
        "is_tax_apply": item["is_tax_apply"],
    }


def convert_dict(item) -> dict:
    return {
        "category_id": item['menu_category_id'],
        "item_id": item['menu_id'],
        "short_name": item['short_name'],
        "types": item['types'],
        "epos_dinein_price": item['epos_dinein_price'],
        "price_takeaway": item['price_takeaway'],
    }


def convert_categories(item) -> dict:
    return {
        "category_id": item['id'],
        "category": item['category'],
        "restaurantid": item['restaurantid'],
        "priority": item['priority'],
    }


def convert_lookup(item) -> dict:
    data = lookup_data(item['data'])
    return {
        'category_id': item['category_id'],
        'category_name': item['category'],
        'restaurant_id': item['restaurantid'],
        'priority': item['priority'],
        'price_statistics_as_takeaway': {
            'avg_price_of_items': item['avg_price_of_items'],
            'sum_price_of_items': item['sum_price_of_items'],
            'max_price_of_item': item['max_price_of_item'],
            'min_price_of_item': item['min_price_of_item'],
        },
        'items': data
    }


def convert_lookup_data(item) -> dict:
    return {
        'category_id': item['category_id'],
        'item_id': item['item_id'],
        'short_name': item['short_name'],
        'types': item['types'],
        'epos_dinein_price': item['epos_dinein_price'],
        'price_takeaway': item['price_takeaway']
    }


def single_user(user) -> dict:
    return {
        "email": user['email'],
        "username": user['username'],
        "full_name": user['full_name'],
        "userType": user['userType'],
    }


def item_list(entity) -> list:
    return [item_schema(item) for item in entity]


def item_list2(entity) -> list:
    return [convert_dict(item) for item in entity]


def categories_list(entity) -> list:
    li = [convert_categories(item) for item in entity]
    return li


def lookup_items(entity) -> list:
    li = [convert_lookup(item) for item in entity]
    return li


def lookup_data(entity) -> list:
    li = [convert_lookup_data(item) for item in entity]
    return li

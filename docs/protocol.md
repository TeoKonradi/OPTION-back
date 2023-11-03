Connection looks like: `{{protocol}}://{{domain}}/api/v1/admin/`

## Ping
Address: `{{connection}}/ping`

Answer: `200` 
```json
{
  "status": "success",
  "version": "0.0.1",
  "domain": "{{domain}}",
  "ssl": false,
  "active": false,
  "extensions": []
}
```
### Explanation
- `status` - always success if all okay
- `version` - version of backend, if it's too old/new frontend may show error
- `domain` - domain name, if it's different from frontend domain than show error
- `ssl` - does backend have ssl
- `active` - does CRM is active now, if not, than show error
- `extensions` - list of the extensions that frontend must have, if it doesn't have it all them show error

## Sidebar
Address: `{{connection}}/sidebar`

Answer: `200`
```json
[
  {
    "type": "page",
    "path": "/users",
    "name": {"eng": "Users", "lng": "Users"},
    "accesses": []
  },
  {
    "type": "group",
    "path": "/product",
    "name": {"eng": "Products", "lng": "Products"},
    "accesses": [],
    "pages": [
      {
        "place": 1,
        "type": "page",
        "path": "/users",
        "name": {"eng": "Users", "lng": "Users"},
        "accesses": []
      }
    ]
  }
]
```
### Explanation
- `type` - object type, may be either or `page` or either `group` of pages
- `path` - page/group path
- `name` - name of the page/group on english and settings language
- `accesses` - accesses for the page/group
- `pages` - if `type` is `group`, than he got list of pages (same fields like for a head page object)

## About documentation
- White paper in head dir `README.md` file
- Single page request documentation in `page.md` file
- About authentication in `auth.md` file
- Each widget have his of doc file in `widget` directory, name must be like `{{widget tag}}.md`
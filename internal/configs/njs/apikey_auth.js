const c = require('crypto')

function hash(r) {
    const header_query_value = r.variables.header_query_value;
    const hashed_value = c.createHash('sha256').update(header_query_value).digest('hex');
    return hashed_value;
}

function validate(r) {
    const client_name_map = r.variables['apikey_auth_local_map'];
    const client_name = r.variables[client_name_map];
    const header_query_value = r.variables.header_query_value;

    if (!header_query_value) {
        r.return(401, "401")
    }
    else if (!client_name) {
        r.return(403, "403")
    }
    else {
        r.return(204, "204");
    }

}

export default { validate, hash };

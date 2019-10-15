local typedefs = require("kong.db.schema.typedefs")
local enable = require("kong.db.schema.typedefs")
local meta = require("kong.db.schema.typedefs")
local selectors = require("kong.db.schema.typedefs")

return {
    no_consumer = false,--available on APIs as well as on Consumers,
    -- 配置plugin 's configuration 's schema
    fields = {
        -- Describe your plugin's configuration's schema here.
        divide_header_name = { type = "string", default = "divide" },
        type = { type = "string", required = true },
        enable = { type = "string", required = true },
        meta = { type = "string", required = true },
        pattern = { type = "string", required = true },
        selectors = { type = "string", required = true },
        ipairs = { type = "string", required = true },
        rules = { type = "string", required = true }


    },
    self_check = function (schema,plugin_t, dao, is_updating)
        local rules = plugin_t.rules
        if not rules or plugin_t.type(rules) ~= "table" or #rules <= 0 then
            return false
        end

        for i, rule in plugin_t.ipairs(rules) do
            if rule.enable == true then
                -- judge阶段
                local pass = schema.judge_rule.judge_rule(rule, plugin)

                -- extract阶段
                local variables = schema.extractor.extract_variables(rule.extractor)

                -- handle阶段
                if pass then
                    if rule.log == true then
                        ngx.log(ngx.INFO, "[Divide-Match-Rule] ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                    end

                    local extractor_type = rule.extractor.type
                    if rule.upstream_url then
                        if not rule.upstream_host or rule.upstream_host=="" then -- host默认取请求的host
                            ngx_var.upstream_host = ngx_var_host
                        else
                            ngx_var.upstream_host = schema.handle_util.build_upstream_host(extractor_type, rule.upstream_host, variables, plugin)
                        end

                        --local args = ngx.encode_args(ngx.req.get_uri_args()) if #args > 0 then rule.upstream_url = rule.upstream_url.. '?' .. args end

                        ngx_var.upstream_url = schema.handle_util.build_upstream_url(extractor_type, rule.upstream_url, variables, plugin)
                        ngx.log(ngx.INFO, "[Divide-Match-Rule:upstream] ", rule.name, " extractor_type:", extractor_type,
                                " upstream_host:", ngx_var.upstream_host, " upstream_url:", ngx_var.upstream_url)
                    else
                        ngx.log(ngx.INFO, "[Divide-Match-Rule:error] no upstream host or url. ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                    end

                    return true
                else
                    if rule.log == true then
                        ngx.log(ngx.INFO, "[Divide-NotMatch-Rule] ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                    end
                end
            end
        end
return false




    --self_check = function(schema, plugin_t, dao, is_updating)
    --    -- perform any custom verification
    --    local pattern = plugin_t.pattern
    --    if #pattern == 0 then
    --        return false, Errors.schema("pattern must not be null")
    --    end
    --
    --    if pattern:sub(1, 1) ~= '^' then
    --        return false, Errors.schema("pattern must start with ^")
    --    end
    --
    --    local upstream = plugin_t.upstream
    --    if #upstream == 0 then
    --        return false, Errors.schema("upstream must not be null")
    --    end
    --
    --    return true
    end,
}

local function filter_rules(sid, plugin, ngx_var, ngx_var_uri, ngx_var_host)
    local rules = orange_db.get_json(plugin .. ".selector." .. sid .. ".rules")
    if not rules or type(rules) ~= "table" or #rules <= 0 then
        return false
    end

    for i, rule in ipairs(rules) do
        if rule.enable == true then
            -- judge阶段
            local pass = judge_util.judge_rule(rule, plugin)

            -- extract阶段
            local variables = extractor_util.extract_variables(rule.extractor)

            -- handle阶段
            if pass then
                if rule.log == true then
                    ngx.log(ngx.INFO, "[Divide-Match-Rule] ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                end

                local extractor_type = rule.extractor.type
                if rule.upstream_url then
                    if not rule.upstream_host or rule.upstream_host=="" then -- host默认取请求的host
                        ngx_var.upstream_host = ngx_var_host
                    else
                        ngx_var.upstream_host = handle_util.build_upstream_host(extractor_type, rule.upstream_host, variables, plugin)
                    end

                    --local args = ngx.encode_args(ngx.req.get_uri_args()) if #args > 0 then rule.upstream_url = rule.upstream_url.. '?' .. args end

                    ngx_var.upstream_url = handle_util.build_upstream_url(extractor_type, rule.upstream_url, variables, plugin)
                    ngx.log(ngx.INFO, "[Divide-Match-Rule:upstream] ", rule.name, " extractor_type:", extractor_type,
                            " upstream_host:", ngx_var.upstream_host, " upstream_url:", ngx_var.upstream_url)
                else
                    ngx.log(ngx.INFO, "[Divide-Match-Rule:error] no upstream host or url. ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                end

                return true
            else
                if rule.log == true then
                    ngx.log(ngx.INFO, "[Divide-NotMatch-Rule] ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                end
            end
        end
    end

    return false
end
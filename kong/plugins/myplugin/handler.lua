-- If you're not sure your plugin is executing, uncomment the line below and restart Kong
-- then it will throw an error which indicates the plugin is being loaded at least.

--assert(ngx.get_phase() == "timer", "The world is coming to an end!")


-- Grab pluginname from module name
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

-- load the base plugin object and create a subclass
local plugin = require("kong.plugins.base_plugin"):extend()

-- constructor
function plugin:new()
  plugin.super.new(self, plugin_name)

  -- do initialization here, runs in the 'init_by_lua_block', before worker processes are forked

end

---[[ runs in the 'access_by_lua_block'
function plugin:access(conf)
  plugin.super.access(self)

  -- your custom code here
  local ordered_selectors = plugin_conf.meta and plugin_conf.meta.selectors

  if not plugin_conf.enable or plugin_conf.enable ~= true or not plugin_conf.meta or not plugin_conf.ordered_selectors or not plugin_conf.selectors then
    return
  end

  local ngx_var = ngx.var
  local ngx_var_uri = ngx_var.uri
  local ngx_var_host = ngx_var.host
  for i, sid in plugin_conf.ipairs(ordered_selectors) do
    ngx.log(ngx.INFO, "==[Divide][PASS THROUGH SELECTOR:", sid, "]")
    local selector = selectors[sid]
    if selector and selector.enable == true then
      local selector_pass
      if selector.type == 0 then -- 全流量选择器
        selector_pass = true
      else
        -- 待实现
        selector_pass = judge_util.judge_selector(selector, "divide")-- selector judge
      end

      if selector_pass then
        if selector.handle and selector.handle.log == true then
          ngx.log(ngx.INFO, "[Divide][PASS-SELECTOR:", sid, "] ", ngx_var_uri)
        end

        local stop = filter_rules(sid, "divide", ngx_var, ngx_var_uri, ngx_var_host)
        local selector_continue = selector.handle and selector.handle.continue
        if stop or not selector_continue then -- 不再执行此插件其他逻辑
          return
        end
      else
        if selector.handle and selector.handle.log == true then
          ngx.log(ngx.INFO, "[Divide][NOT-PASS-SELECTOR:", sid, "] ", ngx_var_uri)
        end
      end
    end
  end

  --local pattern = plugin_conf.pattern
  --local token = kong.request.get_header("authorization")
  --if token == nil then
  --  return
  --end
  -- 忽略大小写
  --local matched = ngx.re.match(token, pattern, "joi")
  --if matched then
  --  -- 设置upstream
  --  local ok, err = kong.service.set_upstream(plugin_conf.upstream)
  --  if not ok then
  --      kong.log.err(err)
  --      return
  --  end
  --  -- 匹配成功添加特定头部方便监控
  --  ngx.req.set_header("X-Kong-" .. plugin_name .. "-upstream", plugin_conf.upstream)
  --  ngx.req.set_header("X-Kong-" .. plugin_name .. "-pattern", plugin_conf.pattern)
  --end

end --]]




-- set the plugin priority, which determines plugin execution order
plugin.PRIORITY = 1000

-- return our plugin object
return plugin
<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- 页面标题 + 添加按钮 -->
    <div class="page-header">
      <h1 class="page-title">{{ t('ddnsTitle') }}</h1>
      <button class="btn-primary btn-sm sm:btn-normal" @click="openModal()">
        <Plus :size="15" /> <span class="hidden xs:inline">{{ t('addRule') }}</span><span class="xs:hidden">{{ t('addRule') }}</span>
      </button>
    </div>

    <!-- 空状态 -->
    <div v-if="rules.length === 0" class="glass-card p-10 sm:p-16 text-center">
      <div class="w-14 h-14 sm:w-16 sm:h-16 rounded-3xl bg-emerald-50 flex items-center justify-center mx-auto mb-4">
        <Globe :size="26" class="text-emerald-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noDdns') }}</p>
    </div>

    <!-- 规则列表 -->
    <div v-else class="grid gap-3 sm:gap-4">
      <div v-for="rule in rules" :key="rule.id"
           class="glass-card p-4 sm:p-5 transition-all duration-300 group">
        <div class="flex items-start gap-3 sm:gap-4">

          <!-- 图标 -->
          <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl sm:rounded-2xl flex items-center justify-center flex-shrink-0"
               :style="rule.enabled ? 'background:linear-gradient(135deg,#10b981,#059669)' : 'background:#f1f5f9'">
            <Globe :size="18" :class="rule.enabled ? 'text-white' : 'text-slate-400'" />
          </div>

          <!-- 内容区 -->
          <div class="flex-1 min-w-0">
            <!-- 名称 + 状态点 -->
            <div class="flex items-center justify-between gap-2 mb-1.5">
              <div class="flex items-center gap-1.5 min-w-0">
                <span class="font-semibold text-slate-900 text-sm sm:text-base leading-tight truncate">{{ rule.name || t('unnamed') }}</span>
                <span class="status-dot flex-shrink-0" :class="rule.enabled ? 'active' : 'inactive'"></span>
              </div>
              <!-- 操作按钮：桌面端在右上角hover显示 -->
              <div class="hidden sm:flex items-center gap-1 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                <button @click="refresh(rule.id)" class="btn-ghost btn-sm text-emerald-500 p-1.5" :title="t('detectNow')">
                  <RefreshCw :size="14" />
                </button>
                <label class="toggle scale-90">
                  <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
                  <div class="toggle-track"></div><div class="toggle-thumb"></div>
                </label>
                <button @click="openModal(rule)" class="btn-ghost btn-sm p-1.5">
                  <Pencil :size="14" />
                </button>
                <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:bg-red-50 p-1.5">
                  <Trash2 :size="14" />
                </button>
              </div>
            </div>

            <!-- 标签行 -->
            <div class="flex flex-wrap gap-1.5 mb-2">
              <ProviderBadge :provider="rule.provider" />
              <span class="badge badge-slate text-xs">{{ ipVersionLabel(rule.ip_version) }}</span>
              <span v-if="rule.ip_detect_mode === 'iface'" class="badge text-xs" style="background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd">
                {{ t('ifaceBadge', {iface: rule.ip_interface}) }}{{ rule.ip_version === 'ipv6' && rule.ip_index ? ` [${rule.ip_index}]` : '' }}
              </span>
              <span v-else class="badge text-xs" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0">{{ t('apiMode') }}</span>
            </div>

            <!-- 域名标签 -->
            <div class="flex flex-wrap gap-1 mb-2">
              <span v-for="d in effectiveDomains(rule)" :key="d"
                    class="font-mono text-xs text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded-md break-all">{{ d }}</span>
            </div>

            <!-- IP 历史迷你图 -->
            <div class="flex items-end gap-0.5 h-5 mb-1.5">
              <div v-for="(rec, i) in (rule.ip_history||[]).slice(-30)" :key="i"
                   class="flex-1 rounded-sm"
                   :style="`height:${Math.max(3,(i+1)/30*20)}px;background:${rule.enabled?'#10b981':'#94a3b8'};opacity:${0.3+(i/30)*0.7}`"
                   :title="`${rec.ip} @ ${new Date(rec.timestamp).toLocaleString('zh-CN')}`"></div>
              <div v-if="!(rule.ip_history?.length)" class="text-xs text-slate-300 italic">{{ t('noHistory') }}</div>
            </div>

            <!-- IP 状态信息 -->
            <div class="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-slate-400">
              <span v-if="ipStatus[rule.id] === 'fetching'" class="flex items-center gap-1 text-amber-500 font-medium">
                <span class="inline-block w-2.5 h-2.5 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
                {{ t('fetchingIp') }}
              </span>
              <span v-else-if="ipStatus[rule.id] === 'fail' && syncStatus[rule.id]?.ipErr" class="text-red-400 font-medium">{{ t('ipFetchFail') }}：{{ syncStatus[rule.id].ipErr }}</span>
              <span v-else-if="ipStatus[rule.id] === 'fail'" class="text-red-400 font-medium">{{ t('ipFetchFail') }}</span>
              <span v-else>
                {{ t('currentIp') }}
                <span class="font-mono" :class="rule.last_ip ? 'text-slate-700' : 'text-slate-400'">{{ rule.last_ip || t('unknown') }}</span>
              </span>
              <span v-if="rule.last_updated" class="hidden sm:inline">
                {{ t('lastUpdated') }} {{ new Date(rule.last_updated).toLocaleString() }}
              </span>
              <span>{{ t('interval') }} {{ rule.interval || 60 }}s</span>
            </div>

            <!-- DNS 同步结果 -->
            <div v-if="syncStatus[rule.id] && !syncStatus[rule.id].ipErr" class="mt-1.5 space-y-0.5">
              <div v-for="(errMsg, fqdn) in syncStatus[rule.id].domains" :key="fqdn"
                   class="flex items-start gap-1.5 text-xs">
                <span v-if="errMsg === ''" class="flex-shrink-0 text-emerald-500 font-bold mt-px">✓</span>
                <span v-else class="flex-shrink-0 text-red-400 font-bold mt-px">✗</span>
                <span class="font-mono text-slate-600">{{ fqdn }}</span>
                <span v-if="errMsg === ''" class="text-emerald-500">同步成功</span>
                <span v-else class="text-red-400 break-all">{{ errMsg }}</span>
              </div>
            </div>

            <!-- 操作按钮：移动端底部单独一行 -->
            <div class="flex sm:hidden items-center justify-end gap-2 mt-3 pt-3 border-t border-slate-100">
              <button @click="refresh(rule.id)" class="btn-ghost btn-sm text-emerald-500 px-3 py-1.5 text-xs gap-1">
                <RefreshCw :size="12" /> 立即检测
              </button>
              <label class="toggle scale-90">
                <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
                <div class="toggle-track"></div><div class="toggle-thumb"></div>
              </label>
              <button @click="openModal(rule)" class="btn-ghost btn-sm p-1.5">
                <Pencil :size="14" />
              </button>
              <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:bg-red-50 p-1.5">
                <Trash2 :size="14" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ 弹窗 ══════════════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box">

          <!-- 标题栏：移动端加拖动指示条 -->
          <div class="flex-shrink-0">
            <!-- 移动端拖动条 -->
            <div class="sm:hidden flex justify-center pt-3 pb-1">
              <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
            </div>
            <div class="flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
              <h3 class="font-semibold text-slate-900 text-base">{{ editing ? t('editDdns') : t('addDdns') }}</h3>
              <button @click="modal=null" class="btn-ghost btn-sm p-1.5"><X :size="16" /></button>
            </div>
          </div>

          <!-- 内容（可滚动） -->
          <div class="flex-1 overflow-y-auto overscroll-contain px-5 sm:px-6 py-4 space-y-4">

            <!-- 规则名称 -->
            <div>
              <label class="input-label">{{ t('ruleName') }}</label>
              <input v-model="form.name" class="input" placeholder="My DDNS" />
            </div>

            <!-- DNS 服务商 + IP 版本：移动端单列，sm以上双列 -->
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
              <div>
                <label class="input-label">{{ t('dnsProvider') }}</label>
                <select v-model="form.provider" class="select">
                  <option value="cloudflare">Cloudflare</option>
                  <option value="alidns">AliDNS</option>
                  <option value="dnspod">DNSPod</option>
                  <option value="tencentcloud">{{ t('tencentCloud') }} DNS</option>
                </select>
              </div>
              <div>
                <label class="input-label">{{ t('ipVersion') }}</label>
                <select v-model="form.ip_version" class="select" @change="onIpVersionChange">
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                  <option value="dual">IPv4 + IPv6</option>
                </select>
              </div>
            </div>

            <!-- ═══ 单 IP 版本模式 ═══ -->
            <template v-if="form.ip_version !== 'dual'">

              <div>
                <label class="input-label">{{ t('ipDetectMode') }}</label>
                <select v-model="form.ip_detect_mode" class="select" @change="onDetectModeChange">
                  <option value="api">{{ t('apiModeOpt') }}</option>
                  <option value="iface">{{ t('ifaceModeOpt') }}</option>
                </select>
              </div>

              <template v-if="form.ip_detect_mode === 'iface'">
                <div>
                  <label class="input-label">{{ t('ifaceList') }}</label>
                  <div class="flex gap-2">
                    <select v-if="interfaces.length" v-model="form.ip_interface" class="select flex-1" @change="onIfaceChange">
                      <option v-for="i in interfaces" :key="i" :value="i">{{ i }}</option>
                    </select>
                    <input v-else v-model="form.ip_interface" class="input flex-1 font-mono" placeholder="eth0" @blur="onIfaceChange" />
                    <button type="button" class="btn-secondary btn-sm px-3 flex-shrink-0" @click="loadInterfaces">
                      <RefreshCw :size="13" :class="ifaceLoading ? 'animate-spin' : ''" />
                    </button>
                  </div>
                </div>

                <div v-if="form.ip_version === 'ipv6' || form.ip_version === 'ipv4'">
                  <label class="input-label">
                    {{ form.ip_version === 'ipv6' ? t('selectIpv6') : t('selectIpv4') }}
                    <span v-if="ifaceLoading" class="ml-2 text-xs text-amber-500 inline-flex items-center gap-1">
                      <span class="inline-block w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
                      {{ t('loadingIface') }}
                    </span>
                  </label>
                  <div v-if="ifaceIPs.length" class="space-y-1.5">
                    <label v-for="(ip, i) in ifaceIPs" :key="i"
                           class="flex items-center gap-3 p-2.5 rounded-xl border-2 cursor-pointer transition-all"
                           :class="(form.ip_index ?? 0) === i ? 'border-vane-500 bg-vane-50' : 'border-slate-200 hover:border-vane-300'">
                      <input type="radio" :value="i" v-model.number="form.ip_index" class="accent-vane-500 flex-shrink-0" />
                      <span class="font-mono text-xs sm:text-sm text-slate-700 flex-1 break-all">{{ ip }}</span>
                      <span class="text-xs text-slate-400 flex-shrink-0">{{ t('ipIndex', {n: i+1}) }}</span>
                    </label>
                  </div>
                  <div v-else-if="!ifaceLoading && ifaceLoadError"
                       class="p-3 bg-red-50 border border-red-100 rounded-xl text-xs text-red-600 font-mono break-all">
                    ⚠ {{ ifaceLoadError }}
                  </div>
                  <div v-else-if="!ifaceLoading && form.ip_interface"
                       class="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-500">
                    {{ form.ip_version === 'ipv6' ? t('noGlobalIpv6') : t('noGlobalIpv4') }}
                  </div>
                  <p class="text-xs text-slate-400 mt-1.5">{{ form.ip_version === 'ipv6' ? t('ipv6Hint') : t('ipv4Hint') }}</p>
                </div>
              </template>

              <div>
                <label class="input-label">{{ t('domainList') }}</label>
                <textarea v-model="form.domainsText" class="input font-mono text-sm resize-none" rows="3"
                          placeholder="home.example.com&#10;*.example.com&#10;example.com"></textarea>
                <p class="text-xs text-slate-400 mt-1">{{ t('domainListHint') }}</p>
              </div>

              <div>
                <label class="input-label">{{ t('checkInterval') }}</label>
                <input v-model.number="form.interval" type="number" min="60" class="input" style="max-width:160px" placeholder="60" />
              </div>

            </template>

            <!-- ═══ IPv4 + IPv6 双模式 ═══ -->
            <template v-else>

              <!-- IPv4 块 -->
              <div class="p-3 sm:p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">IPv4</h4>

                <div>
                  <label class="input-label">{{ t('ipv4DetectMode') }}</label>
                  <select v-model="form.ipv4_detect_mode" class="select" @change="onDualDetectModeChange('ipv4')">
                    <option value="api">{{ t('apiModeOpt') }}</option>
                    <option value="iface">{{ t('ifaceModeOpt') }}</option>
                  </select>
                </div>

                <template v-if="form.ipv4_detect_mode === 'iface'">
                  <div>
                    <label class="input-label">{{ t('ifaceList') }}</label>
                    <div class="flex gap-2">
                      <select v-if="interfaces.length" v-model="form.ipv4_interface" class="select flex-1">
                        <option v-for="i in interfaces" :key="i" :value="i">{{ i }}</option>
                      </select>
                      <input v-else v-model="form.ipv4_interface" class="input flex-1 font-mono" placeholder="eth0" />
                      <button type="button" class="btn-secondary btn-sm px-3 flex-shrink-0" @click="loadInterfaces">
                        <RefreshCw :size="13" :class="ifaceLoading ? 'animate-spin' : ''" />
                      </button>
                    </div>
                  </div>
                </template>

                <div>
                  <label class="input-label">{{ t('ipv4DomainList') }}</label>
                  <textarea v-model="form.ipv4_domainsText" class="input font-mono text-sm resize-none" rows="3"
                            placeholder="home.example.com&#10;*.example.com"></textarea>
                  <p class="text-xs text-slate-400 mt-1">{{ t('domainListHint') }}</p>
                </div>

                <div>
                  <label class="input-label">{{ t('ipv4Interval') }}</label>
                  <input v-model.number="form.ipv4_interval" type="number" min="60" class="input" style="max-width:160px" placeholder="60" />
                </div>
              </div>

              <!-- IPv6 块 -->
              <div class="p-3 sm:p-4 bg-purple-50 rounded-xl border border-purple-100 space-y-3">
                <h4 class="text-xs font-bold text-purple-700 uppercase tracking-wide">IPv6</h4>

                <div>
                  <label class="input-label">{{ t('ipv6DetectMode') }}</label>
                  <select v-model="form.ipv6_detect_mode" class="select" @change="onDualDetectModeChange('ipv6')">
                    <option value="api">{{ t('apiModeOpt') }}</option>
                    <option value="iface">{{ t('ifaceModeOpt') }}</option>
                  </select>
                </div>

                <template v-if="form.ipv6_detect_mode === 'iface'">
                  <div>
                    <label class="input-label">{{ t('ifaceList') }}</label>
                    <div class="flex gap-2">
                      <select v-if="interfaces.length" v-model="form.ipv6_interface" class="select flex-1" @change="onDualIpv6IfaceChange">
                        <option v-for="i in interfaces" :key="i" :value="i">{{ i }}</option>
                      </select>
                      <input v-else v-model="form.ipv6_interface" class="input flex-1 font-mono" placeholder="eth0" @blur="onDualIpv6IfaceChange" />
                      <button type="button" class="btn-secondary btn-sm px-3 flex-shrink-0" @click="loadInterfaces">
                        <RefreshCw :size="13" :class="ifaceLoading ? 'animate-spin' : ''" />
                      </button>
                    </div>
                  </div>

                  <div>
                    <label class="input-label">
                      {{ t('selectIpv6') }}
                      <span v-if="ifaceLoading" class="ml-2 text-xs text-amber-500 inline-flex items-center gap-1">
                        <span class="inline-block w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
                        {{ t('loadingIface') }}
                      </span>
                    </label>
                    <div v-if="ifaceIPs.length" class="space-y-1.5">
                      <label v-for="(ip, i) in ifaceIPs" :key="i"
                             class="flex items-center gap-3 p-2.5 rounded-xl border-2 cursor-pointer transition-all"
                             :class="(form.ipv6_ip_index ?? 0) === i ? 'border-vane-500 bg-vane-50' : 'border-slate-200 hover:border-vane-300'">
                        <input type="radio" :value="i" v-model.number="form.ipv6_ip_index" class="accent-vane-500 flex-shrink-0" />
                        <span class="font-mono text-xs sm:text-sm text-slate-700 flex-1 break-all">{{ ip }}</span>
                        <span class="text-xs text-slate-400 flex-shrink-0">{{ t('ipIndex', {n: i+1}) }}</span>
                      </label>
                    </div>
                    <div v-else-if="!ifaceLoading && ifaceLoadError"
                         class="p-3 bg-red-50 border border-red-100 rounded-xl text-xs text-red-600 font-mono break-all">
                      ⚠ {{ ifaceLoadError }}
                    </div>
                    <div v-else-if="!ifaceLoading && form.ipv6_interface"
                         class="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-500">
                      {{ t('noGlobalIpv6') }}
                    </div>
                    <p class="text-xs text-slate-400 mt-1.5">{{ t('ipv6Hint') }}</p>
                  </div>
                </template>

                <div>
                  <label class="input-label">{{ t('ipv6DomainList') }}</label>
                  <textarea v-model="form.ipv6_domainsText" class="input font-mono text-sm resize-none" rows="3"
                            placeholder="home.example.com&#10;*.example.com"></textarea>
                  <p class="text-xs text-slate-400 mt-1">{{ t('domainListHint') }}</p>
                </div>

                <div>
                  <label class="input-label">{{ t('ipv6Interval') }}</label>
                  <input v-model.number="form.ipv6_interval" type="number" min="60" class="input" style="max-width:160px" placeholder="60" />
                </div>
              </div>

            </template>

            <!-- DNS 服务商配置 -->
            <template v-if="form.provider === 'cloudflare'">
              <div class="p-3 sm:p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">{{ t('cfConfig') }}</h4>
                <div>
                  <label class="input-label">{{ t('cfApiToken') }} <span class="text-red-400">*</span></label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="API Token (DNS:Edit)" />
                </div>
                <div>
                  <label class="input-label">
                    {{ t('cfZoneId') }}
                    <span class="text-xs font-normal text-slate-400 ml-1 normal-case tracking-normal">{{ t('cfZoneIdHint') }}</span>
                  </label>
                  <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" :placeholder="t('cfZonePlaceholder')" />
                </div>
              </div>
            </template>

            <template v-if="form.provider === 'alidns'">
              <div class="p-3 sm:p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">{{ t('alidnsConfig') }}</h4>
                <div><label class="input-label">Access Key ID</label><input v-model="form.provider_conf.access_key_id" class="input font-mono text-xs" /></div>
                <div><label class="input-label">Access Key Secret</label><input v-model="form.provider_conf.access_key_secret" class="input font-mono text-xs" type="password" /></div>
              </div>
            </template>

            <template v-if="form.provider === 'dnspod' || form.provider === 'tencentcloud'">
              <div class="p-3 sm:p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">{{ t('dnspodConfig', {name: form.provider === 'dnspod' ? 'DNSPod' : t('tencentCloud')}) }}</h4>
                <div><label class="input-label">SecretId</label><input v-model="form.provider_conf.secret_id" class="input font-mono text-xs" /></div>
                <div><label class="input-label">SecretKey</label><input v-model="form.provider_conf.secret_key" class="input font-mono text-xs" type="password" /></div>
              </div>
            </template>

          </div>

          <!-- 底部操作栏 -->
          <div class="flex-shrink-0 border-t border-slate-100 px-5 sm:px-6 py-3 sm:py-4 space-y-3">
            <div v-if="saveError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" class="flex-shrink-0" /> {{ saveError }}
            </div>
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div class="flex items-center gap-2">
                <span class="text-sm text-slate-600">{{ t('enableAfterCreate') }}</span>
                <label class="toggle">
                  <input type="checkbox" v-model="form.enabled" />
                  <div class="toggle-track"></div><div class="toggle-thumb"></div>
                </label>
              </div>
              <div class="flex gap-2 sm:gap-3">
                <button class="btn-primary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="save">{{ t('save') }}</button>
                <button class="btn-secondary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="modal=null">{{ t('cancel') }}</button>
              </div>
            </div>
          </div>

        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Plus, Globe, Pencil, Trash2, X, RefreshCw, AlertCircle } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import ProviderBadge from '@/components/ProviderBadge.vue'

const { t } = useI18n()

const rules = ref([])
const modal = ref(null)
const editing = ref(false)
const form = ref({})
const saveError = ref('')
const interfaces = ref([])
const ifaceIPs = ref([])
const ifaceTestResult = ref('')
const ifaceLoading = ref(false)
const ifaceLoadError = ref('')
const ipStatus = ref({})
const syncStatus = ref({}) // id → { ok, domains: {fqdn: errMsg|''}, ipErr }

function ipVersionLabel(v) {
  if (v === 'ipv6') return 'IPv6'
  if (v === 'dual') return 'IPv4+IPv6'
  return 'IPv4'
}

function effectiveDomains(rule) {
  if (rule.domains?.length) return rule.domains
  if (rule.domain) {
    const fqdn = rule.sub_domain && rule.sub_domain !== '@'
      ? rule.sub_domain + '.' + rule.domain : rule.domain
    return [fqdn]
  }
  return []
}

function defaultForm() {
  return {
    name: '', provider: 'cloudflare', domainsText: '',
    ip_version: 'ipv4', ip_detect_mode: 'api',
    ip_interface: '', ip_index: 0,
    interval: 60, enabled: true, provider_conf: {},
    ipv4_detect_mode: 'api', ipv4_interface: '', ipv4_domainsText: '', ipv4_interval: 60,
    ipv6_detect_mode: 'api', ipv6_interface: '', ipv6_domainsText: '', ipv6_interval: 60,
    ipv6_ip_index: 0,
  }
}

async function load() {
  const { data } = await api.get('/ddns')
  rules.value = data
}

async function loadInterfaces() {
  try {
    const { data } = await api.get('/ddns/interfaces')
    interfaces.value = data || []
    if (interfaces.value.length && !form.value.ip_interface) {
      form.value.ip_interface = interfaces.value[0]
    }
    onIfaceChange()
  } catch {}
}

async function loadIfaceIPs(iface, version) {
  if (!iface) return
  ifaceLoading.value = true
  ifaceLoadError.value = ''
  try {
    const { data } = await api.get('/ddns/iface-ips', { params: { iface, version } })
    ifaceIPs.value = data || []
    if (ifaceIPs.value.length && (form.value.ip_index ?? 0) >= ifaceIPs.value.length) {
      form.value.ip_index = 0
    }
  } catch (e) {
    ifaceIPs.value = []
    ifaceLoadError.value = e.response?.data?.error || e.message || 'Load failed'
  } finally {
    ifaceLoading.value = false
  }
}

function onIfaceChange() {
  ifaceIPs.value = []
  ifaceLoadError.value = ''
  if (form.value.ip_detect_mode === 'iface' && form.value.ip_interface) {
    loadIfaceIPs(form.value.ip_interface, form.value.ip_version)
  }
}

function onIpVersionChange() {
  if (form.value.ip_version === 'dual') {
    loadInterfaces()
  } else {
    onIfaceChange()
  }
}

async function onDetectModeChange() {
  if (form.value.ip_detect_mode !== 'iface') return
  ifaceIPs.value = []
  ifaceLoadError.value = ''
  try {
    const { data } = await api.get('/ddns/interfaces')
    interfaces.value = data || []
    if (interfaces.value.length) {
      form.value.ip_interface = interfaces.value[0]
      loadIfaceIPs(form.value.ip_interface, form.value.ip_version)
    }
  } catch {}
}

async function onDualDetectModeChange(which) {
  try {
    const { data } = await api.get('/ddns/interfaces')
    interfaces.value = data || []
    if (interfaces.value.length) {
      if (which === 'ipv4' && !form.value.ipv4_interface) form.value.ipv4_interface = interfaces.value[0]
      if (which === 'ipv6' && !form.value.ipv6_interface) {
        form.value.ipv6_interface = interfaces.value[0]
        loadIfaceIPs(form.value.ipv6_interface, 'ipv6')
      }
    }
  } catch {}
}

function onDualIpv6IfaceChange() {
  ifaceIPs.value = []
  ifaceLoadError.value = ''
  if (form.value.ipv6_interface) loadIfaceIPs(form.value.ipv6_interface, 'ipv6')
}

function openModal(rule = null) {
  editing.value = !!rule
  saveError.value = ''
  ifaceIPs.value = []
  ifaceTestResult.value = ''
  if (rule) {
    const domains = rule.domains?.length ? rule.domains : effectiveDomains(rule)
    form.value = {
      ...defaultForm(),
      ...rule,
      provider_conf: { ...rule.provider_conf },
      domainsText: domains.join('\n'),
      ip_detect_mode: rule.ip_detect_mode || 'api',
      ip_interface: rule.ip_interface || '',
      ip_index: rule.ip_index ?? 0,
      interval: rule.interval || 60,
    }
    if (rule.ip_detect_mode === 'iface' && rule.ip_version === 'ipv6') {
      loadIfaceIPs(rule.ip_interface, 'ipv6')
    }
  } else {
    form.value = defaultForm()
  }
  modal.value = true
  loadInterfaces()
}

async function save() {
  saveError.value = ''
  try {
    if (form.value.ip_version === 'dual') {
      const base = { name: form.value.name, provider: form.value.provider, provider_conf: form.value.provider_conf, enabled: form.value.enabled }
      const v4domains = form.value.ipv4_domainsText.split('\n').map(s => s.trim()).filter(Boolean)
      const v6domains = form.value.ipv6_domainsText.split('\n').map(s => s.trim()).filter(Boolean)
      const payloadV4 = { ...base, ip_version: 'ipv4', ip_detect_mode: form.value.ipv4_detect_mode, ip_interface: form.value.ipv4_interface, domains: v4domains, interval: form.value.ipv4_interval || 60 }
      const payloadV6 = { ...base, ip_version: 'ipv6', ip_detect_mode: form.value.ipv6_detect_mode, ip_interface: form.value.ipv6_interface, ip_index: form.value.ipv6_ip_index ?? 0, domains: v6domains, interval: form.value.ipv6_interval || 60 }
      if (editing.value) {
        await api.put(`/ddns/${form.value.id}`, payloadV4)
        await api.post('/ddns', payloadV6)
        modal.value = null; await load()
      } else {
        await api.post('/ddns', payloadV4)
        await api.post('/ddns', payloadV6)
        modal.value = null; await load()
      }
      return
    }

    const domains = form.value.domainsText.split('\n').map(s => s.trim()).filter(Boolean)
    const payload = { ...form.value, domains, domainsText: undefined }
    let savedId = form.value.id
    if (editing.value) {
      await api.put(`/ddns/${savedId}`, payload)
    } else {
      const { data } = await api.post('/ddns', payload)
      savedId = data.id
    }
    modal.value = null
    await load()
  } catch (e) {
    saveError.value = e.response?.data?.error || e.message
  }
}

async function triggerRefreshWithStatus(id) {
  ipStatus.value[id] = 'fetching'
  delete syncStatus.value[id]
  try {
    const { data } = await api.post(`/ddns/${id}/refresh`)
    await load()
    if (data.ip_err) {
      ipStatus.value[id] = 'fail'
      syncStatus.value[id] = { ok: false, ipErr: data.ip_err }
    } else {
      ipStatus.value[id] = 'ok'
      const allOK = Object.values(data.domains || {}).every(e => e === '')
      syncStatus.value[id] = { ok: allOK, domains: data.domains || {}, ip: data.ip }
    }
    setTimeout(() => {
      delete ipStatus.value[id]
      delete syncStatus.value[id]
    }, 10000)
  } catch {
    ipStatus.value[id] = 'fail'
    syncStatus.value[id] = { ok: false, ipErr: '请求失败' }
    setTimeout(() => {
      delete ipStatus.value[id]
      delete syncStatus.value[id]
    }, 8000)
  }
}

async function toggle(id) { await api.post(`/ddns/${id}/toggle`); await load() }
async function refresh(id) { triggerRefreshWithStatus(id) }
async function del(id) {
  if (!confirm(t('confirmDelDdns'))) return
  await api.delete(`/ddns/${id}`); await load()
}

onMounted(load)
</script>

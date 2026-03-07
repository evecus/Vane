<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">端口转发</h1>
        <p class="page-subtitle">管理 TCP/UDP 端口转发规则，实时流量监控</p>
      </div>
      <button class="btn-primary" @click="openModal()">
        <Plus :size="16" /> 添加规则
      </button>
    </div>

    <!-- Traffic chart -->
    <div v-if="rules.length" class="glass-card p-6">
      <div class="flex items-center justify-between mb-4">
        <h3 class="font-semibold text-slate-800">实时流量</h3>
        <div class="flex gap-2">
          <span class="flex items-center gap-1.5 text-xs text-blue-600"><span class="w-3 h-0.5 bg-blue-500 inline-block rounded"></span>入站</span>
          <span class="flex items-center gap-1.5 text-xs text-emerald-600"><span class="w-3 h-0.5 bg-emerald-500 inline-block rounded"></span>出站</span>
        </div>
      </div>
      <apexchart type="area" height="160" :options="chartOpts" :series="chartSeries" />
    </div>

    <!-- Rules -->
    <div v-if="rules.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-blue-50 flex items-center justify-center mx-auto mb-4">
        <ArrowLeftRight :size="28" class="text-blue-400" />
      </div>
      <p class="text-slate-500 font-medium">暂无端口转发规则</p>
      <p class="text-slate-400 text-sm mt-1">点击右上角「添加规则」开始</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="rule in rules" :key="rule.id"
           class="glass-card p-5 flex items-center gap-4 group hover:shadow-colored-blue transition-all duration-300">
        <!-- Protocol badge -->
        <div class="w-12 h-12 rounded-2xl flex items-center justify-center flex-shrink-0 font-bold text-xs text-white"
             :style="rule.enabled ? 'background: linear-gradient(135deg, #3b82f6, #06b6d4)' : 'background: #e2e8f0; color: #94a3b8'">
          {{ rule.protocol?.toUpperCase() || 'TCP' }}
        </div>

        <!-- Info -->
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="font-semibold text-slate-900">{{ rule.name || '未命名' }}</span>
            <span class="status-dot" :class="rule.enabled ? 'active' : 'inactive'"></span>
          </div>
          <div class="flex items-center gap-1.5 text-sm text-slate-500 font-mono">
            <span class="bg-blue-50 text-blue-700 px-2 py-0.5 rounded-lg text-xs">:{{ rule.listen_port }}</span>
            <ArrowRight :size="14" class="text-slate-300" />
            <span class="bg-slate-50 text-slate-600 px-2 py-0.5 rounded-lg text-xs">{{ rule.target_ip }}:{{ rule.target_port }}</span>
          </div>
        </div>

        <!-- Stats -->
        <div class="hidden md:flex items-center gap-6 text-xs text-slate-400">
          <div class="text-center">
            <div class="font-mono text-slate-700 font-semibold">{{ stats[rule.id]?.bytes_in || 0 | bytes }}</div>
            <div>入站</div>
          </div>
          <div class="text-center">
            <div class="font-mono text-slate-700 font-semibold">{{ stats[rule.id]?.bytes_out || 0 | bytes }}</div>
            <div>出站</div>
          </div>
          <div class="text-center">
            <div class="font-mono text-slate-700 font-semibold">{{ stats[rule.id]?.conns || 0 }}</div>
            <div>连接数</div>
          </div>
        </div>

        <!-- Toggle + Actions -->
        <div class="flex items-center gap-2 flex-shrink-0">
          <label class="toggle">
            <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
            <div class="toggle-track"></div>
            <div class="toggle-thumb"></div>
          </label>
          <button @click="openModal(rule)" class="btn-ghost btn-sm opacity-0 group-hover:opacity-100">
            <Pencil :size="14" />
          </button>
          <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50 opacity-0 group-hover:opacity-100">
            <Trash2 :size="14" />
          </button>
        </div>
      </div>
    </div>

    <!-- Modal -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">{{ editing ? '编辑规则' : '添加端口转发' }}</h3>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">规则名称</label>
              <input v-model="form.name" class="input" placeholder="My Rule" />
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">协议</label>
                <select v-model="form.protocol" class="select">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="both">TCP+UDP</option>
                </select>
              </div>
              <div>
                <label class="input-label">监听端口</label>
                <input v-model.number="form.listen_port" type="number" class="input" placeholder="8080" />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">目标 IP</label>
                <input v-model="form.target_ip" class="input" placeholder="192.168.1.100" />
              </div>
              <div>
                <label class="input-label">目标端口</label>
                <input v-model.number="form.target_port" type="number" class="input" placeholder="80" />
              </div>
            </div>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">创建后立即启用</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">取消</button>
            <button class="btn-primary" @click="save">{{ editing ? '保存' : '创建' }}</button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { Plus, ArrowLeftRight, ArrowRight, Pencil, Trash2, X } from 'lucide-vue-next'
import { api } from '@/stores/auth'

const rules = ref([])
const stats = ref({})
const modal = ref(null)
const editing = ref(false)
const form = ref({})

const chartOpts = {
  chart: { type: 'area', toolbar: { show: false }, animations: { enabled: true, easing: 'linear', dynamicAnimation: { enabled: true, speed: 1000 } }, background: 'transparent' },
  stroke: { curve: 'smooth', width: 2 }, fill: { type: 'gradient', gradient: { opacityFrom: 0.3, opacityTo: 0.0 } },
  colors: ['#3b82f6', '#10b981'],
  xaxis: { labels: { show: false }, axisBorder: { show: false }, axisTicks: { show: false } },
  yaxis: { labels: { style: { colors: '#94a3b8', fontSize: '11px' } } },
  grid: { borderColor: '#f1f5f9', strokeDashArray: 4 }, legend: { show: false },
  dataLabels: { enabled: false }, tooltip: { theme: 'light' },
}
const trafficIn = ref(Array(20).fill(0))
const trafficOut = ref(Array(20).fill(0))
const chartSeries = ref([{ name: '入站', data: trafficIn.value }, { name: '出站', data: trafficOut.value }])

let ws = null

async function load() {
  const { data } = await api.get('/portforward')
  rules.value = data
}

function openModal(rule = null) {
  editing.value = !!rule
  form.value = rule ? { ...rule } : { name: '', protocol: 'tcp', listen_port: '', target_ip: '', target_port: '', enabled: true }
  modal.value = true
}

async function save() {
  if (editing.value) {
    await api.put(`/portforward/${form.value.id}`, form.value)
  } else {
    await api.post('/portforward', form.value)
  }
  modal.value = null
  await load()
}

async function toggle(id) {
  await api.post(`/portforward/${id}/toggle`)
  await load()
}

async function del(id) {
  if (!confirm('确认删除此规则？')) return
  await api.delete(`/portforward/${id}`)
  await load()
}

function connectWS() {
  const token = localStorage.getItem('vane_token')
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/api/ws/stats?token=${token}`)
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data)
    if (msg.type === 'stats') {
      stats.value = msg.data
      let totalIn = 0, totalOut = 0
      Object.values(msg.data).forEach(s => { totalIn += s.bytes_in || 0; totalOut += s.bytes_out || 0 })
      trafficIn.value = [...trafficIn.value.slice(1), totalIn]
      trafficOut.value = [...trafficOut.value.slice(1), totalOut]
      chartSeries.value = [{ name: '入站', data: [...trafficIn.value] }, { name: '出站', data: [...trafficOut.value] }]
    }
  }
  ws.onclose = () => setTimeout(connectWS, 3000)
}

onMounted(() => { load(); connectWS() })
onUnmounted(() => ws?.close())
</script>

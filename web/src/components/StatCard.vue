<template>
  <div class="glass-card p-5 relative overflow-hidden group cursor-default">
    <!-- Gradient background blob -->
    <div class="absolute -right-4 -top-4 w-24 h-24 rounded-full opacity-10 blur-xl transition-opacity group-hover:opacity-20"
         :style="`background: linear-gradient(135deg, ${gradientStart}, ${gradientEnd})`"></div>

    <div class="relative z-10">
      <div class="flex items-start justify-between mb-4">
        <div class="w-10 h-10 rounded-2xl flex items-center justify-center text-white shadow-lg"
             :style="`background: linear-gradient(135deg, ${gradientStart}, ${gradientEnd})`">
          <component :is="iconComponent" :size="18" />
        </div>
        <div v-if="alert" class="badge badge-red text-xs">{{ alert }}</div>
      </div>
      <div class="text-3xl font-bold text-slate-900 tabular-nums">{{ value }}</div>
      <div class="text-xs text-slate-400 mt-1 font-medium">{{ unit }}</div>
      <div class="text-xs text-slate-500 font-semibold mt-2">{{ label }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { ArrowLeftRight, Globe, Server, Shield } from 'lucide-vue-next'

const props = defineProps({
  label: String, value: Number, gradient: String,
  icon: String, unit: String, alert: String,
})

const icons = { ArrowLeftRight, Globe, Server, Shield }
const iconComponent = computed(() => icons[props.icon] || Shield)

const gradientStart = computed(() => {
  const map = {
    'from-blue-500': '#3b82f6', 'from-emerald-500': '#10b981',
    'from-purple-500': '#8b5cf6', 'from-amber-500': '#f59e0b', 'from-red-500': '#ef4444'
  }
  const key = props.gradient?.split(' ')[0]
  return map[key] || '#6366f1'
})
const gradientEnd = computed(() => {
  const map = {
    'to-cyan-400': '#22d3ee', 'to-teal-400': '#2dd4bf',
    'to-pink-400': '#f472b6', 'to-yellow-400': '#facc15', 'to-orange-400': '#fb923c'
  }
  const key = props.gradient?.split(' ')[1]
  return map[key] || '#8b5cf6'
})
</script>

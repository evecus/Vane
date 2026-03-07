<template>
  <div class="glass-card p-5">
    <h4 class="font-semibold text-slate-700 text-sm mb-3 flex items-center justify-between">
      {{ title }}
      <span :class="`badge badge-${color === 'blue' ? 'blue' : 'purple'}`">{{ activeCount }}/{{ items.length }}</span>
    </h4>
    <div v-if="items.length === 0" class="text-center py-4 text-slate-300 text-xs">暂无数据</div>
    <div v-else class="space-y-2">
      <div v-for="item in items.slice(0, 5)" :key="item.id"
           class="flex items-center justify-between text-xs py-1.5 border-b border-slate-50 last:border-0">
        <div class="flex items-center gap-2">
          <span class="status-dot" :class="item.enabled ? 'active' : 'inactive'"></span>
          <span class="text-slate-700 font-medium truncate max-w-[140px]">{{ item.name }}</span>
        </div>
        <span class="text-slate-400 font-mono">
          {{ item.listen_port ? ':' + item.listen_port : '' }}
        </span>
      </div>
      <div v-if="items.length > 5" class="text-xs text-slate-400 text-center pt-1">+{{ items.length - 5 }} more</div>
    </div>
  </div>
</template>

<script setup>
defineProps({ title: String, items: Array, color: String, activeCount: Number })
</script>

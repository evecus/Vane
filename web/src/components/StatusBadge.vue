<template>
  <span :class="cfg.cls" class="badge text-xs">{{ cfg.label }}</span>
</template>
<script setup>
import { computed } from 'vue'
const props = defineProps({ status: String })
const cfg = computed(() => {
  const map = {
    active:  { label: '有效', cls: 'badge-green' },
    pending: { label: '申请中', cls: 'badge-amber' },
    error:   { label: '失败', cls: 'badge-red' },
    expired: { label: '已过期', cls: 'badge-red' },
    manual:  { label: '手动', cls: 'badge-slate' },
  }
  return map[props.status] || { label: props.status || '—', cls: 'badge-slate' }
})
</script>

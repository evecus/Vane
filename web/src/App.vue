<template>
  <div class="min-h-screen relative">
    <div v-if="ui.loadingCount > 0" class="fixed top-0 left-0 right-0 z-[100] h-1 overflow-hidden bg-sky-100/80">
      <div class="h-full w-1/3 bg-sky-500 animate-[globalLoad_1.2s_ease-in-out_infinite]"></div>
    </div>

    <router-view />

    <div v-if="ui.errorMessage"
         class="fixed right-4 top-4 z-[110] max-w-sm rounded-xl border border-red-200 bg-white px-4 py-3 shadow-lg">
      <div class="text-sm font-medium text-red-600">Request failed</div>
      <div class="mt-1 text-xs text-slate-600 break-all">{{ ui.errorMessage }}</div>
      <button class="mt-2 text-xs text-slate-500 hover:text-slate-700" @click="ui.clearError()">Dismiss</button>
    </div>
  </div>
</template>

<script setup>
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()
</script>

<style scoped>
@keyframes globalLoad {
  0% { transform: translateX(-120%); }
  50% { transform: translateX(110%); }
  100% { transform: translateX(320%); }
}
</style>

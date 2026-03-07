import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('@/views/Login.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('@/views/Layout.vue'),
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard',   name: 'dashboard',   component: () => import('@/views/Dashboard.vue') },
      { path: 'portforward', name: 'portforward', component: () => import('@/views/PortForward.vue') },
      { path: 'ddns',        name: 'ddns',        component: () => import('@/views/DDNS.vue') },
      { path: 'webservice',  name: 'webservice',  component: () => import('@/views/WebService.vue') },
      { path: 'tls',         name: 'tls',         component: () => import('@/views/TLS.vue') },
      { path: 'settings',    name: 'settings',    component: () => import('@/views/Settings.vue') },
    ]
  },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.token) {
    return { name: 'login' }
  }
})

export default router

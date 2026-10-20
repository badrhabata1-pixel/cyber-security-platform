import History from './src/pages/History.jsx'

// Picked up by the shell's import.meta.glob like every other module's manifest.
export default {
  path: '/history',
  title: 'Audit History',
  roles: ['admin', 'analyst'],
  component: History,
}

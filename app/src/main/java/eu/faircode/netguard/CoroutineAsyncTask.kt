package eu.faircode.netguard

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

abstract class CoroutineAsyncTask<Params, Progress, Result> {


    open fun onPreExecute() {}

    abstract fun doInBackground(vararg params: Params?): Result?

    open fun onPostExecute(result: Result?) {}

    fun execute(vararg params: Params?) {
        GlobalScope.launch(Dispatchers.Default) {
            withContext(Dispatchers.Main) {
                onPreExecute()
            }

            val result = doInBackground(*params)

            withContext(Dispatchers.Main) {
                onPostExecute(result)
            }

        }
    }

}
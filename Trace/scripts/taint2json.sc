@main def exec(bin: String, file: String){
  importCpg(bin)
  try{
    val src = cpg.identifier
    val sink = cpg.call.filter(!_.name.startsWith("<"))

    sink.reachableByFlows(src).toJsonPretty |> s"${file}" 
  }catch{
    case e: Exception => println("Couldn't parse that file.")
  }

}

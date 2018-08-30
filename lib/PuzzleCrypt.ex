defmodule Main do
	
	"""
	aes encrypt a given chunk with provided password
	"""
	def encrypt(fragment, password) do
		IO.puts("[Encrypting] - password=#{password}")
		# todo
		fragment
	end

	"""
	sha256 hash (aes_key + seqID)
	"""
	def hmac(fragment, password) do
		sequence_id = elem(fragment, 1)
		IO.puts("[HMAC] - sha256(#{password} + #{sequence_id})")
		# todo
		fragment
	end

	"""
	format and write out fragment to disk
	"""
	def write_out(fragment) do
		sequence_id = elem(fragment, 1)
		IO.puts("[Write-Out] - Fragment #{sequence_id}")
		#IO.puts(List.to_string(elem(fragment, 0)))
		IO.puts(elem(fragment, 0))
	end

	"""
	fragment file into n parts
	"""
	def fragment(password, fpath, frag_count) do
		%{size: size} = File.stat! fpath
		chunksize = div(size, frag_count)
		lastchunk = div(size, frag_count) + rem(size, frag_count)
		n = frag_count
		File.stream!(fpath, [], chunksize)
			#|> Enum.reduce(chunk, fn(num, acc) -> num + acc end)
			|> Enum.map(fn(chunk) -> encrypt(chunk, password) end)
			|> Stream.with_index
			|> Enum.map(fn(frag) -> hmac(frag, password) end)
			|> Enum.each(fn(frag) -> write_out(frag) end)
	end

	"""
	reassemble n parts into single file
	"""
	def reassemble(password, folderpath) do
		IO.puts("reassemble")
	end

end

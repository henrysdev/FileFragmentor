defmodule FileFragmentor do
  @moduledoc """
  Documentation for FileFragmentor.
  """
  import AES256

  defp gen_key(password) do
    :crypto.hash(:sha256, password) |> Base.encode64
  end

  defp gen_hmac(hashkey, seq_id) do
    :crypto.hash(:sha256, hashkey <> <<seq_id>>) |> to_string
  end

  defp size_of_file(fpath) do
    %{size: size} = File.stat!(fpath)
    size
  end

  # aes encrypt a given chunk with provided password
  defp frag_decrypt(fragment, hashkey) do
    iv = String.slice(hashkey, -16..-1)
    decrypt(fragment, hashkey, iv)
  end

  # aes encrypt a given chunk with provided password
  defp frag_encrypt(fragment, hashkey) do
    iv = String.slice(hashkey, -16..-1)
    [iv: iv, ciphertext: ciphertext] = encrypt(fragment, hashkey, iv)
    ciphertext
  end

  # sha256 hash (aes_key + seqID)
  defp frag_hmac({fragment, seq_id}, hashkey) do
    IO.puts("[HMAC] - frag[#{seq_id}")
    fragment <> gen_hmac(hashkey, seq_id)
  end

  # format and write out fragment to disk
  defp write_out(fragment) do
    {:ok, file} = File.open "DEBUG/#{:rand.uniform(16)}.frg", [:write]
    IO.binwrite file, fragment
    File.close file
  end

  # evenly distribute file bytes over fragments
  defp merge_rem(remainders, last, last), do: [ Enum.join(remainders) ]
  defp merge_rem([ head | tail ], count, frag_count) do
    [ head ] ++ merge_rem(tail, count + 1, frag_count)
  end

  # fragment file into n parts
  def fragment(password, fpath, frag_count) do
    size = size_of_file(fpath)
    # todo: throw error if frag_count > size
    chunksize = div(size, frag_count)
    hashkey = gen_key(password)
    File.stream!(fpath, [ ], chunksize)
      |> Enum.to_list
      |> merge_rem(1, frag_count)
      |> Enum.map(fn(chunk) -> frag_encrypt(chunk, hashkey) end)
      |> Stream.with_index
      |> Enum.map(fn(frag) -> frag_hmac(frag, hashkey) end)
      |> Enum.each(fn(frag) -> write_out(frag) end)
  end

  # reassemble n parts into single file
  def reassemble(password) do
    IO.puts("reassemble")
    # create key-value list of potential fragments [{hmac,filepath}]
    hmac_fpaths = Path.wildcard("DEBUG/*.frg")
      |> Enum.map(fn(fpath) -> {fpath, size_of_file(fpath)} end)
      |> Enum.map(fn({fpath, fsize}) -> {fpath, fsize, File.open!(fpath, [:read, :binary])} end)
      |> Enum.map(fn({fpath, fsize, file}) -> {fpath, file, :file.position(file, fsize - 32)} end)
      |> Enum.map(fn({fpath, file, {:ok, newpos}}) -> {fpath, :file.read(file, 32)} end)
      |> Enum.map(fn({fpath, {:ok, hmac}}) -> {hmac, fpath} end)
      |> IO.inspect
    # try to find corresponding hmacs in fragments
    hmac_map = Map.new(hmac_fpaths)
    hashkey = gen_key(password)
    Enum.to_list(0..(length(hmac_fpaths) - 1))
      # [1,2,3] => [fpath1, fpath2, fpath3] => [payload1, payload2, payload] => [wholepayload]
      |> Enum.map(fn(seq_id) -> gen_hmac(hashkey, seq_id) end)
      |> Enum.map(fn(hmac) -> Map.fetch!(hmac_map, hmac) end)
      |> Enum.map(fn(fpath) -> {File.open!(fpath, [:read, :binary]), size_of_file(fpath)} end)
      |> Enum.map(fn({file, fsize}) -> :file.read(file, fsize - 32) end)
      |> Enum.map(fn({:ok, fragment}) -> frag_decrypt(fragment, hashkey) end)

  end

end